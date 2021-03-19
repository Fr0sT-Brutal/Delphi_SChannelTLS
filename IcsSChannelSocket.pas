{
  ICS TWSocket descendant that performs TLS communication by means of
  Windows SChannel.
  Automatically processes SChannel connection bug.
  Supports establishing and finishing TLS channel over existing connection.

  (c) Fr0sT-Brutal
  
  License MIT
}

unit IcsSChannelSocket;

interface

uses
  SysUtils, Classes, Windows, WinSock,
  JwaWinError, JwaSspi,
  OverbyteIcsWSocket, OverbyteIcsWSockBuf, OverbyteIcsLogger, OverbyteIcsUtils,
  SChannel.Utils;

const
  WS_OK = 0; // WinSock success code

type
  // ICS TWSocket descendant supporting TLS
  TSChannelWSocket = class(TWSocket)
  strict protected
      FSecure: Boolean;
      FChannelState: TChannelState;
      FSessionData: TSessionData;
      FHandShakeData: THandShakeData;
      FhContext: CtxtHandle;
      FHandshakeBug: Boolean;
      FPrevFlags: TSessionFlags; // previous state of session flags
      FAddrIsIP: Boolean;
      FSendBuffer: TBytes;  // buffer that receives encrypted data to be sent
      FRecvBuffer: TBuffer; // buffer that receives encrypted data from server
      FDecrBuffer: TBuffer; // buffer that receives decrypted data from server
      FSizes: SecPkgContext_StreamSizes;
      FPayloadReadCount : Int64; // counters of unencrypted (payload) traffic
      FPayloadWriteCount: Int64;
      // event handlers
      FOnTLSDone: TNotifyEvent;
      FOnTLSShutdown: TNotifyEvent;

      // overrides
      procedure   AssignDefaultValue; override;
      procedure   TriggerSessionConnectedSpecial(Error : Word); override;
      function    TriggerDataAvailable(Error : Word) : Boolean; override;
      procedure   TriggerSessionClosed(Error: Word); override;
      function    GetRcvdCount : LongInt; override;
      function    DoRecv(var Buffer : TWSocketData;
                         BufferSize : Integer;
                         Flags      : Integer) : Integer; override;
      function    RealSend(var Data : TWSocketData; Len : Integer) : Integer; override;
      // new methods
      procedure   SChannelLog(LogOption : TLogOption; const Msg: string);
      procedure   DoHandshakeStart;
      procedure   DoHandshakeProcess;
      procedure   DoHandshakeSuccess;
      procedure   StartTLS;
      procedure   ShutdownTLS;
      procedure   SetSecure(const Value: Boolean);
      procedure   SetSessionData(const SessionData: TSessionData);
  public
      constructor Create(AOwner : TComponent); override;
      destructor  Destroy; override;
      procedure   Listen; override;
      procedure   Shutdown(How : Integer); override;
      procedure   PostFD_EVENT(Event: Cardinal);
  published
      // Indicates whether TLS is currently used. Effect of setting the property
      // depends on current state. @br
      // Socket is **not** connected:
      //   - Setting @name to @True: TLS handshake will be established
      //     automatically as soon as socket is connected.
      //   - Setting @name to @False: work as usual (no TLS)
      //
      // Socket **is** connected:
      //   - Setting @name to @True: TLS handshake will be started immediately
      //     over existing connection
      //   - Setting @name to @False: TLS shutdown will be executed immediately
      //     without closing the connection
      property Secure: Boolean read FSecure write SetSecure;
      // Traffic counter for incoming payload.
      // `TWSocket.ReadCount` property reflects encrypted traffic
      property PayloadReadCount: Int64 read FPayloadReadCount;
      // Traffic counter for outgoing payload.
      // `TWSocket.WriteCount` property reflects encrypted traffic
      property PayloadWriteCount: Int64 read FPayloadWriteCount;
      // TLS Session data that allows fine tuning of TLS handshake. Also it could
      // contain shared credentials used by multiple sockets. Fields must be
      // assigned before starting TLS handshake (otherwise exception is raised).
      // Note that some fields are assigned internally based on other values
      // (f.ex., `sfNoServerVerify` flag is enabled if connecting to IP).
      // Initial values are returned when secure connection is finished.
      // ! Session data is finalized in destructor, closing and zeroing any
      // non-shared handles.
      property SessionData: TSessionData read FSessionData write SetSessionData;
      // Event is called when TLS handshake is established successfully
      property OnTLSDone: TNotifyEvent read FOnTLSDone write FOnTLSDone;
      // Event is called when TLS handshake is shut down
      property OnTLSShutdown: TNotifyEvent read FOnTLSShutdown write FOnTLSShutdown;
  end;

implementation

const
    S_Msg_HandshakeTDAErr = 'Handshake - ! error [%d] in TriggerDataAvailable';
    S_Msg_SettingSessionData = 'Setting SessionData is prohibited when secure channel is active';

// Check if address is a dotted numeric address like 192.161.124.32
function AddrIsIP(const Addr: string): Boolean;
var
    IPAddr  : u_long;
begin
    IPAddr := WSocket_inet_addr(PAnsiChar(AnsiString(Addr)));
    Result := (IPAddr <> u_long(INADDR_NONE));
end;

constructor TSChannelWSocket.Create(AOwner: TComponent);
begin
    SChannel.Utils.Init;
    inherited Create(AOwner);
end;

destructor TSChannelWSocket.Destroy;
begin
    inherited;
    FinSession(FSessionData);
end;

// Cleanup on creation and before connection
procedure TSChannelWSocket.AssignDefaultValue;
begin
    inherited;

    FChannelState := chsNotStarted;
    FHandShakeData := Default(THandShakeData);
    DeleteContext(FhContext);
    FHandshakeBug := False;
    FSendBuffer := nil;
    FRecvBuffer := Default(TBuffer);
    FDecrBuffer := Default(TBuffer);
    FSizes := Default(SecPkgContext_StreamSizes);
    FPayloadReadCount := 0;
    FPayloadWriteCount := 0;
    FPrevFlags := [];
    FAddrIsIP := False;
end;

// Get the number of bytes received, decrypted and waiting to be read
function TSChannelWSocket.GetRcvdCount: LongInt;
begin
    if FChannelState = chsEstablished then
        Result := FRecvBuffer.DataLen
    else
        Result := inherited GetRcvdCount;
end;

// Actual receive data
function TSChannelWSocket.DoRecv(var Buffer: TWSocketData; BufferSize,
  Flags: Integer): Integer;

    // Copies already decrypted data from FDecrBuffer to Buffer
    // Uses external variables: Buffer, BufferSize
    function RecvFromBuffer: Integer;
    begin
        if Integer(FDecrBuffer.DataLen) < BufferSize then
            Result := FDecrBuffer.DataLen
        else
            Result := BufferSize;
        Move(FDecrBuffer.Data[FDecrBuffer.DataStartIdx], Buffer^, Result);
        Inc(FDecrBuffer.DataStartIdx, Result);
        Dec(FDecrBuffer.DataLen, Result);
        Inc(FPayloadReadCount, Result);
    end;

var
    res: Integer;
    pFreeSpace: TWSocketData;
    scRet: SECURITY_STATUS;
    cbWritten: DWORD;
begin
    // SChannel not used or not established yet - call inherited to receive raw
    if FChannelState <> chsEstablished then
    begin
        Result := inherited;
        Exit;
    end;

    // There's already decrypted data in buffer - copy from it and imitate FD_READ event
    if FDecrBuffer.DataLen > 0 then
    begin
        Result := RecvFromBuffer;
        if FState = wsConnected then
            PostFD_EVENT(FD_READ);
        Exit;
    end;

    // Handshake established - receive and decrypt

    // Here we're sure that FDecrBuffer is empty
    FDecrBuffer.DataStartIdx := 0;

    // For some mysterious reason DoRecv requires "var"...
    // In FRecvBuffer data always starts from the beginning
    pFreeSpace := Pointer(@FRecvBuffer.Data[FRecvBuffer.DataLen]);
    res := inherited DoRecv(pFreeSpace, Length(FRecvBuffer.Data) - Integer(FRecvBuffer.DataLen), Flags);
    if res <= 0 then
        Exit(res);
    Inc(FRecvBuffer.DataLen, res);
    scRet := DecryptData(
        FhContext, FSizes, Pointer(FRecvBuffer.Data), FRecvBuffer.DataLen,
        Pointer(FDecrBuffer.Data), Length(FDecrBuffer.Data), cbWritten);
    case scRet of
        SEC_E_OK, SEC_E_INCOMPLETE_MESSAGE, SEC_I_CONTEXT_EXPIRED:
            begin
                SChannelLog(loSslDevel, Format(S_Msg_Received, [res, cbWritten]));
                if scRet = SEC_I_CONTEXT_EXPIRED then
                    SChannelLog(loSslInfo, S_Msg_SessionClosed);
                FDecrBuffer.DataLen := cbWritten;
                Result := RecvFromBuffer;
            end;
        SEC_I_RENEGOTIATE:
            begin
                SChannelLog(loSslInfo, S_Msg_Renegotiate);
                DoHandshakeStart;
                Result := 0;
            end;
        else
            Result := SOCKET_ERROR; // shouldn't happen
    end; // case
end;

// Actual send data
function TSChannelWSocket.RealSend(var Data : TWSocketData; Len : Integer) : Integer;
var
    EncryptedLen: Cardinal;
    Sent: Integer;
begin
    // SChannel not used or not established yet - call inherited to send raw
    if FChannelState <> chsEstablished then
    begin
        Result := inherited;
        Exit;
    end;

    // Handshake established - encrypt and send
    EncryptData(FhContext, FSizes, Data, Len, PByte(FSendBuffer), Length(FSendBuffer), EncryptedLen);
    SChannelLog(loSslDevel, Format(S_Msg_Sending, [Len, EncryptedLen]));
    Sent := inherited RealSend(TWSocketData(FSendBuffer), EncryptedLen);

    if Sent <= 0 then
    begin
        raise ESSPIError.CreateWinAPI('sending payload to server', 'Send', WSocket_WSAGetLastError);
        Result := Sent;
        Exit;
    end;

    Inc(FPayloadWriteCount, Sent);
    // ! Return length of payload
    Result := Len;
end;

// Socket connected - internal event. Start handshake
procedure TSChannelWSocket.TriggerSessionConnectedSpecial(Error: Word);
begin
    { Error occured / no SChannel used / HTTP tunnel or Socks isn't ready yet, signal connect as usual }
    if not FSecure or (Error <> WS_OK) or (FSocksState <> socksData)
      // TODO: change in parent class is required
      {or (FHttpTunnelState <> htsData) } then begin
        inherited;
        Exit;
    end;

    SChannelLog(loSslInfo, S_Msg_StartingTLS);
    StartTLS;
end;

// Data incoming. Handle handshake or ensure decrypted data is received
function TSChannelWSocket.TriggerDataAvailable(Error: Word): Boolean;
begin
    case FChannelState of
        // No secure channel / Channel established - default
        chsNotStarted,
        chsEstablished, chsShutdown:
            begin
                Result := inherited;
            end;

        // Handshaking in progress - special handling
        chsHandshake:
            begin
                if (Error <> WS_OK) then
                begin
                    SChannelLog(loSslErr, Format(S_Msg_HandshakeTDAErr, [Error]));
                    TriggerSessionConnected(Error);
                    InternalClose(TRUE, Error);
                    Result := False;
                    Exit;
                end;

                Result := True;
                DoHandshakeProcess;
            end;

        else
            Result := False; // compiler happy
    end; // case
end;

// TWSocket.ASyncReceive finishes when there's no data in socket but we could
// still have something already decrypted in internal buffer. Make sure we
// consume it all
procedure TSChannelWSocket.TriggerSessionClosed(Error: Word);
begin
    try
        if FChannelState = chsEstablished then
            while FDecrBuffer.DataLen > 0 do
                if not TriggerDataAvailable(WS_OK) then
                    Break;

{$IFNDEF NO_DEBUG_LOG}
        if CheckLogOptions(loWsockInfo) then
            if FSecure then
                DebugLog(loWsockInfo, Format('TriggerSessionClosed. Payload R %d, W %d, total R %d, W %d',
                    [FPayloadReadCount, FPayloadWriteCount, FReadCount, FWriteCount]))
            else
                DebugLog(loWsockInfo, Format('TriggerSessionClosed. Total R %d, W %d',
                    [FReadCount, FWriteCount]));
{$ENDIF}
        inherited;
    except
        on E:Exception do
            HandleBackGroundException(E, 'TriggerSessionClosed');
    end;
end;

// SChannel-specific output
procedure TSChannelWSocket.SChannelLog(LogOption: TLogOption; const Msg: string);
begin
{$IFNDEF NO_DEBUG_LOG}
    if CheckLogOptions(LogOption) then
        DebugLog(LogOption, SChannel.Utils.LogPrefix + Msg);
{$ENDIF}
end;

// Start handshake process
procedure TSChannelWSocket.DoHandshakeStart;
var
    BytesSent: Integer;
begin
    FChannelState := chsHandshake;
    FHandShakeData.Stage := hssNotStarted;

    try
        // Generate hello
        DoClientHandshake(FSessionData, FHandShakeData);
        Assert(FHandShakeData.Stage = hssSendCliHello);

        // Send hello to server
        BytesSent := Send(FHandShakeData.OutBuffers[0].pvBuffer, FHandShakeData.OutBuffers[0].cbBuffer);
        if BytesSent > 0 then
            SChannelLog(loSslDevel, Format(S_Msg_HShStageW1Success, [BytesSent]))
        else
            SChannelLog(loSslErr, Format(S_Msg_HShStageW1Fail, [WSocket_WSAGetLastError, WSocketErrorMsgFromErrorCode(WSocket_WSAGetLastError)]));

        // Prepare to read hello from server
        SetLength(FHandShakeData.IoBuffer, IO_BUFFER_SIZE);
        FHandShakeData.cbIoBuffer := 0;
        FHandShakeData.Stage := hssReadSrvHello;
    finally
        if Length(FHandShakeData.OutBuffers) > 0 then
            g_pSSPI.FreeContextBuffer(FHandShakeData.OutBuffers[0].pvBuffer); // Free output buffer
        SetLength(FHandShakeData.OutBuffers, 0);
    end;
end;

// Handshake in process
procedure TSChannelWSocket.DoHandshakeProcess;
var
    cbData: Integer;
begin
    // Read next chunk from server
    if FHandShakeData.Stage = hssReadSrvHello then
    begin
        cbData := Receive((PByte(FHandShakeData.IoBuffer) + FHandShakeData.cbIoBuffer),
            Length(FHandShakeData.IoBuffer) - Integer(FHandShakeData.cbIoBuffer));
        // ! Although this function is called from TriggerDataAvailable,
        // WSAEWOULDBLOCK could happen so we just ignore receive errors
        if cbData <= 0 then
        begin
            SChannelLog(loSslDevel, Format(S_Msg_HShStageRFail, [WSocket_WSAGetLastError, WSocketErrorMsgFromErrorCode(WSocket_WSAGetLastError)]));
            Exit;
        end;
        SChannelLog(loSslDevel, Format(S_Msg_HShStageRSuccess, [cbData]));
        Inc(FHandShakeData.cbIoBuffer, cbData);
    end;

    // Decode hello
    try
        try
            DoClientHandshake(FSessionData, FHandShakeData);
        except on E: ESSPIError do
            // Hide Windows handshake bug and restart the process for the first time
            if (FHandShakeData.Stage = hssReadSrvHello) and IsWinHandshakeBug(E.SecStatus)
                and not FHandshakeBug then
            begin
                SChannelLog(loSslErr, Format(S_Msg_HandshakeBug, [E.Message]));
                FHandshakeBug := True;
                DeleteContext(FHandShakeData.hContext);
                DoHandshakeStart;
                Exit;
            end
            else
                raise;
        end;

        // Send token if needed
        if FHandShakeData.Stage in [hssReadSrvHelloContNeed, hssReadSrvHelloOK] then
        begin
            if (FHandShakeData.OutBuffers[0].cbBuffer > 0) and (FHandShakeData.OutBuffers[0].pvBuffer <> nil) then
            begin
                cbData := Send(FHandShakeData.OutBuffers[0].pvBuffer, FHandShakeData.OutBuffers[0].cbBuffer);
                if cbData = Integer(FHandShakeData.OutBuffers[0].cbBuffer) then
                    SChannelLog(loSslDevel, Format(S_Msg_HShStageW2Success, [cbData]))
                else
                    SChannelLog(loSslErr, Format(S_Msg_HShStageW2Fail, [WSocket_WSAGetLastError, WSocketErrorMsgFromErrorCode(WSocket_WSAGetLastError)]));
                g_pSSPI.FreeContextBuffer(FHandShakeData.OutBuffers[0].pvBuffer); // Free output buffer
                SetLength(FHandShakeData.OutBuffers, 0);
            end;

            if FHandShakeData.Stage = hssReadSrvHelloContNeed then
            begin
                FHandShakeData.Stage := hssReadSrvHello;
                Exit;
            end;

            if FHandShakeData.Stage = hssReadSrvHelloOK then
            begin
                DoHandshakeSuccess;
                TriggerSessionConnected(WS_OK);
                Exit;
            end;
        end;

    finally
        if Length(FHandShakeData.OutBuffers) > 0 then
            g_pSSPI.FreeContextBuffer(FHandShakeData.OutBuffers[0].pvBuffer); // Free output buffer
        SetLength(FHandShakeData.OutBuffers, 0);
    end;
end;

// Perform actions on successful handshake.
// Helper method, called from TriggerDataAvailable only, extracted for simplicity
procedure TSChannelWSocket.DoHandshakeSuccess;
begin
    FhContext := FHandShakeData.hContext;
    FHandShakeData.Stage := hssDone;
    FChannelState := chsEstablished;
    SChannelLog(loSslInfo, S_Msg_Established);
    if FHandShakeData.cbIoBuffer > 0 then
        SChannelLog(loSslInfo, Format(S_Msg_HShExtraData, [FHandShakeData.cbIoBuffer]));

    // Don't pass host addr if it's IP otherwise verification would fail
    if FAddrIsIP then
        CheckServerCert(FhContext, '')
    else
        CheckServerCert(FhContext, Addr);

    SChannelLog(loSslInfo, S_Msg_SrvCredsAuth);
    InitBuffers(FhContext, FSendBuffer, FSizes);
    SetLength(FRecvBuffer.Data, Length(FSendBuffer));
    SetLength(FDecrBuffer.Data, FSizes.cbMaximumMessage);
    // Copy received extra data (0 length will work too)
    Move(Pointer(FHandShakeData.IoBuffer)^, Pointer(FRecvBuffer.Data)^, FHandShakeData.cbIoBuffer);
    Inc(FRecvBuffer.DataLen, FHandShakeData.cbIoBuffer);
    FHandShakeData := Default(THandShakeData);

    if Assigned(FOnTLSDone) then
        FOnTLSDone(Self);
end;

// Change internal FSecure field and, if connected, run StartTLS/ShutdownTLS
procedure TSChannelWSocket.SetSecure(const Value: Boolean);
begin
    if FSecure = Value then Exit; // no change

    if Value then
    begin
        // already connected - start handshake
        if FState = wsConnected then
            StartTLS;
    end
    else
    begin
        // already connected - shutdown TLS
        if FState = wsConnected then
            ShutdownTLS;
    end;

    // Only set field if no exceptions happened
    FSecure := Value;
end;

// Imitate FD_* event on a socket. Mostly useful with FD_READ to have DataAvailable
// with buffering socket implementations
procedure TSChannelWSocket.PostFD_EVENT(Event: Cardinal);
begin
    PostMessage(Handle, FMsg_WM_ASYNCSELECT, WPARAM(FHSocket), IcsMakeLong(Event, 0));
end;

// Start TLS handshake process
procedure TSChannelWSocket.StartTLS;
var pCreds: PSessionCreds;
begin
    // Create and init session data if not inited yet or finished (unlikely)
    pCreds := GetSessionCredsPtr(FSessionData);
    if SecIsNullHandle(pCreds.hCreds) then
    begin
      CreateSessionCreds(pCreds^);
      SChannelLog(loSslInfo, S_Msg_CredsInited);
    end;

    // Save initial flags
    FPrevFlags := FSessionData.Flags;
    // Check if Addr is IP and set flag if yes
    FAddrIsIP := AddrIsIP(Addr);
    if FAddrIsIP then
    begin
        SChannelLog(loSslInfo, Format(S_Msg_AddrIsIP, [Addr]));
        Include(FSessionData.Flags, sfNoServerVerify);
    end;

    FHandShakeData.ServerName := Addr;
    FhContext := Default(CtxtHandle);
    DoHandshakeStart;
end;

// Shutdown TLS channel without closing the socket connection
procedure TSChannelWSocket.ShutdownTLS;
var
    OutBuffer: SecBuffer;
begin
    SChannelLog(loSslInfo, S_Msg_ShuttingDownTLS);

    // Restore previous value of flags that could've been auto-set by
    // current connect to an IP
    FSessionData.Flags := FPrevFlags;

    // Send a close_notify alert to the server and close down the connection.
    GetShutdownData(FSessionData, FhContext, OutBuffer);
    if OutBuffer.cbBuffer > 0 then
    begin
        SChannelLog(loSslDevel, Format(S_Msg_SendingShutdown, [OutBuffer.cbBuffer]));
        FChannelState := chsShutdown;
        Send(OutBuffer.pvBuffer, OutBuffer.cbBuffer);
        g_pSSPI.FreeContextBuffer(OutBuffer.pvBuffer);
    end;
    DeleteContext(FhContext);

    if Assigned(FOnTLSShutdown) then
        FOnTLSShutdown(Self);

    FChannelState := chsNotStarted;
end;

// Override for inherited method - deny listening in secure mode
procedure TSChannelWSocket.Listen;
begin
    { Check if we really want to use SChannel in server }
    if FSecure then
        raise ESocketException.Create(S_Err_ListeningNotSupported);

    { No SChannel used, Listen as usual }
    inherited;
end;

// Override for inherited method - shutdown TLS channel before closing the connection
// (ignoring exceptions and don't waiting for peer response)
procedure TSChannelWSocket.Shutdown(How: Integer);
begin
    // Secure channel not established - run default
    if FChannelState <> chsEstablished then begin
        inherited ShutDown(How);
        Exit;
    end;

    // Send a close_notify alert to the server and close the connection.
    try
        ShutdownTLS;
        // Currently we don't wait for data to be sent or server replies, just shutdown
        inherited ShutDown(How);
    // Just log an exception, don't let it go
    except on E: Exception do
        SChannelLog(loSslErr, E.Message);
    end;
end;

procedure TSChannelWSocket.SetSessionData(const SessionData: TSessionData);
begin
    // Allow setting only when channel is not established
    if FChannelState <> chsNotStarted then
        raise ESocketException.Create(S_Msg_SettingSessionData);

    FSessionData := SessionData;
end;

end.
