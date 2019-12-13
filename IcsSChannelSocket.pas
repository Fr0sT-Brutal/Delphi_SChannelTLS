{
  ICS TWSocket descendant that performs TLS communication by means of
  Windows SChannel.

  (c) Fr0sT-Brutal
  
  License MIT
}

unit IcsSChannelSocket;

interface

uses
  SysUtils, Classes, Windows, WinSock,
  JwaWinError, JwaSspi,
  OverbyteIcsWSocket, OverbyteIcsWSockBuf, OverbyteIcsLogger,
  SChannel.Utils;

const
  WS_OK = 0; // WinSock success code

type
  TBuffer = record
      Data: TBytes;
      DataStartIdx: Integer;
      DataLen: Cardinal;
  end;

  TSChannelWSocket = class(TWSocket)
  strict protected
      FSecure: Boolean;
      FChannelState: TChannelState;
      FSessionData: TSessionData;
      FHandShakeData: THandShakeData;
      FhContext: CtxtHandle;
      FHandshakeBug: Boolean;
      FSendBuffer: TBytes;  // buffer that receives encrypted data to be sent
      FRecvBuffer: TBuffer; // buffer that receives encrypted data from server
      FDecrBuffer: TBuffer; // buffer that receives decrypted data from server
      FSizes: SecPkgContext_StreamSizes;
      FPayloadReadCount : Int64; // counters of unencrypted (payload) traffic
      FPayloadWriteCount: Int64;

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
  public
      constructor Create(AOwner : TComponent); override;
      procedure   Listen; override;
      procedure   Shutdown(How : Integer); override;
  published
      // If True, connect is established via TLS
      property    Secure: Boolean          read FSecure            write FSecure;
      // Payload traffic counters. Read/WriteCount props reflect encrypted traffic
      property    PayloadReadCount: Int64  read FPayloadReadCount;
      property    PayloadWriteCount: Int64 read FPayloadWriteCount;
  end;

implementation

constructor TSChannelWSocket.Create(AOwner: TComponent);
begin
    SChannel.Utils.Init;
    inherited Create(AOwner);
end;

procedure TSChannelWSocket.AssignDefaultValue;
begin
    inherited;

    FChannelState := chsNotStarted;
    FHandShakeData := Default(THandShakeData);
    FinSession(FSessionData);
    FSessionData := Default(TSessionData);
    DeleteContext(FhContext);
    FHandshakeBug := False;
    FSendBuffer := nil;
    FRecvBuffer := Default(TBuffer);
    FDecrBuffer := Default(TBuffer);
    FSizes := Default(SecPkgContext_StreamSizes);
    FPayloadReadCount := 0;
    FPayloadWriteCount := 0;
end;

// Deny listening in secure mode
procedure TSChannelWSocket.Listen;
begin
    { Check if we really want to use SChannel in server }
    if FSecure then
        raise ESocketException.Create('Listening is not supported with SChannel yet');

    { No SChannel used, Listen as usual }
    inherited;
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
    pCurrBuffer: TWSocketData;
    scRet: SECURITY_STATUS;
    cbRead: DWORD;
begin
    // SChannel not used - call inherited
    if not FSecure then begin
        Result := inherited;
        Exit;
    end;

    // Channel not established yet - receive raw
    if FChannelState <> chsEstablished then
    begin
        Result := inherited;
        Exit;
    end;

    // There's already decrypted data in buffer - copy from it and call empty
    // Receive to re-launch FD_WRITE event
    if FDecrBuffer.DataLen > 0 then
    begin
        Result := RecvFromBuffer;
        pCurrBuffer := nil;
        inherited DoRecv(pCurrBuffer, 0, Flags);
        Exit;
    end;

    // Handshake established - receive and decrypt

    // Here we're sure that FDecrBuffer is empty
    FDecrBuffer.DataStartIdx := 0;

    // For some mysterious reason DoRecv requires "var"...
    // In FRecvBuffer data always starts from the beginning
    pCurrBuffer := Pointer(@FRecvBuffer.Data[FRecvBuffer.DataLen]);
    res := inherited DoRecv(pCurrBuffer, Length(FRecvBuffer.Data) - Integer(FRecvBuffer.DataLen), Flags);
    if res <= 0 then
        Exit(res);
    Inc(FRecvBuffer.DataLen, res);
    scRet := DecryptData(
        FhContext, FSizes, Pointer(FRecvBuffer.Data), FRecvBuffer.DataLen,
        Pointer(FDecrBuffer.Data), Length(FDecrBuffer.Data), cbRead);
    case scRet of
        SEC_E_OK, SEC_E_INCOMPLETE_MESSAGE, SEC_I_CONTEXT_EXPIRED:
            begin
                SChannelLog(loSslDevel, Format('Received %d bytes of encrypted data / %d bytes of payload', [res, cbRead]));
                if scRet = SEC_I_CONTEXT_EXPIRED then
                    SChannelLog(loSslInfo, 'Server closed the connection [SEC_I_CONTEXT_EXPIRED]');
                FDecrBuffer.DataLen := cbRead;
                Result := RecvFromBuffer;
            end;
        SEC_I_RENEGOTIATE:
            begin
                SChannelLog(loSslInfo, 'Server requested renegotiate');
                DoHandshakeStart;
                Result := 0;
            end;
        else
            raise ESSPIError.CreateFmt('DecryptMessage unexpected result %s', [SecStatusErrStr(scRet)]);
    end; // case
end;

// Actual send data
function TSChannelWSocket.RealSend(var Data : TWSocketData; Len : Integer) : Integer;
var
    EncryptedLen: Cardinal;
    Sent: Integer;
begin
    // SChannel not used - call inherited
    if not FSecure then begin
        Result := inherited;
        Exit;
    end;

    // Channel not established yet - send raw
    if FChannelState <> chsEstablished then
    begin
        Result := inherited;
        Exit;
    end;

    // Handshake established - encrypt and send
    EncryptData(FhContext, FSizes, Data, Len, PByte(FSendBuffer), Length(FSendBuffer), EncryptedLen);
    SChannelLog(loSslDevel, Format('Sending %d bytes of payload, %d bytes encrypted', [Len, EncryptedLen]));
    Sent := inherited RealSend(TWSocketData(FSendBuffer), EncryptedLen);

    if Sent <= 0 then
    begin
        raise ESSPIError.CreateWinAPI('Error sending payload to server: "%s"', 'Send', WSocket_WSAGetLastError);
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
    { Error occured / no SChannel used, signal connect as usual }
    if not FSecure or (Error <> WS_OK) then begin
        inherited;
        Exit;
    end;

    InitSession(FSessionData);
    SChannelLog(loSslInfo, 'Credentials initialized');
    SChannelLog(loSslInfo, 'Connected, starting TLS handshake');

    FHandShakeData.ServerName := Addr;
    FhContext := Default(CtxtHandle);
    DoHandshakeStart;
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
                    SChannelLog(loSslErr, Format('Handshake - ! error [%d] in TriggerDataAvailable', [Error]));
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
            SChannelLog(loSslDevel, Format('Handshake stage 1 - %d bytes sent', [BytesSent]))
        else
            SChannelLog(loSslErr, 'Handshake - ! error sending data');

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
            SChannelLog(loSslDevel, Format('Handshake - no data received or error receiving [%d]', [WSocket_WSAGetLastError]));
            Exit;
        end;
        SChannelLog(loSslDevel, Format('Handshake - %d bytes received', [cbData]));
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
                SChannelLog(loSslErr, Format('Handshake bug: "%s", retrying', [E.Message]));
                FHandshakeBug := True;
                DeleteContext(FHandShakeData.hContext);
                DoHandshakeStart;
                Exit;
            end
            else
                raise E;
        end;

        // Send token if needed
        if FHandShakeData.Stage in [hssReadSrvHelloContNeed, hssReadSrvHelloOK] then
        begin
            if (FHandShakeData.OutBuffers[0].cbBuffer > 0) and (FHandShakeData.OutBuffers[0].pvBuffer <> nil) then
            begin
                cbData := Send(FHandShakeData.OutBuffers[0].pvBuffer, FHandShakeData.OutBuffers[0].cbBuffer);
                if cbData = Integer(FHandShakeData.OutBuffers[0].cbBuffer) then
                    SChannelLog(loSslDevel, Format('Handshake stage 2 - %d bytes sent', [cbData]))
                else
                    SChannelLog(loSslErr, 'Handshake - ! data sent partially');
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
    FHandShakeData := Default(THandShakeData);
    FHandShakeData.Stage := hssDone;
    FChannelState := chsEstablished;
    SChannelLog(loSslInfo, 'Handshake established');
    CheckServerCert(FhContext, Addr);
    SChannelLog(loSslInfo, 'Server credentials authenticated');
    InitBuffers(FhContext, FSendBuffer, FSizes);
    SetLength(FRecvBuffer.Data, Length(FSendBuffer));
    SetLength(FDecrBuffer.Data, FSizes.cbMaximumMessage);
end;

procedure TSChannelWSocket.Shutdown(How: Integer);
var
    OutBuffer: SecBuffer;
begin
    if FHSocket = INVALID_SOCKET then
        Exit;
    // Secure channel not established -
    if not FSecure or not (FChannelState in [chsEstablished, chsShutdown]) then begin
        inherited ShutDown(How);
        Exit;
    end;
    SChannelLog(loSslInfo, 'Shutting down');

    // Send a close_notify alert to the server and close down the connection.
    try
        GetShutdownData(FSessionData, FhContext, OutBuffer);
        if OutBuffer.cbBuffer > 0 then
        begin
            SChannelLog(loSslDevel, Format('Sending shutdown notify - %d bytes of data', [OutBuffer.cbBuffer]));
            FChannelState := chsShutdown;
            Send(OutBuffer.pvBuffer, OutBuffer.cbBuffer);
            g_pSSPI.FreeContextBuffer(OutBuffer.pvBuffer);
            // Currently we don't wait for data to be sent, just shutdown
            inherited ShutDown(How);
        end;
    // Just log an exception, don't let it go
    except on E: Exception do
        SChannelLog(loSslErr, E.Message);
    end;
end;

end.
