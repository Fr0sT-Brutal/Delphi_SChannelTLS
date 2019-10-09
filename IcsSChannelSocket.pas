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
      FSendBuffer: TBytes;  // buffer that receives encrypted data to be sent
      FRecvBuffer: TBuffer; // buffer that receives encrypted data from server
      FDecrBuffer: TBuffer; // buffer that receives decrypted data from server
      FSizes: SecPkgContext_StreamSizes;
      FPayloadReadCount : Int64; // counters of unencrypted (payload) traffic
      FPayloadWriteCount: Int64;
      FShutdownHow: Integer;

      // overrides
      procedure   AssignDefaultValue; override;
      procedure   TriggerSessionConnectedSpecial(Error : Word); override;
      function    TriggerDataAvailable(Error : Word) : Boolean; override;
      procedure   TriggerDataSent(Error : Word); override;
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

// Get the number of char received and waiting to be read
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
        if FDecrBuffer.DataLen < BufferSize then
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

    // There's already decrypted data in buffer - copy from it
    if FDecrBuffer.DataLen > 0 then
    begin
        Result := RecvFromBuffer;
        // We haven't received data from socket - there could be no more DataAvailable
        // event. Empty recv will launch it again.
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
    res := inherited DoRecv(pCurrBuffer, Length(FRecvBuffer.Data) - FRecvBuffer.DataLen, Flags);
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
                FDecrBuffer.DataLen := cbRead;
                Result := RecvFromBuffer;
                if scRet = SEC_I_CONTEXT_EXPIRED then
                    SChannelLog(loSslInfo, 'Server closed the connection [SEC_I_CONTEXT_EXPIRED]');
            end;
        SEC_I_RENEGOTIATE:
            begin
                SChannelLog(loSslInfo, 'Server requested renegotiate');
                FHandShakeData.ServerName := Addr;
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
    InitSession(FSessionData);
    SChannelLog(loSslInfo, 'Credentials initialized');
    SChannelLog(loSslInfo, 'Connected, starting TLS handshake');

    { Error occured / no SChannel used, signal connect as usual }
    if not FSecure or (Error <> 0) then begin
        inherited;
        Exit;
    end;

    FHandShakeData.ServerName := Addr;
    FhContext := Default(CtxtHandle);
    DoHandshakeStart;
end;

// Data incoming. Handle handshake
function TSChannelWSocket.TriggerDataAvailable(Error: Word): Boolean;
begin
    // Custom process only if handshaking
    if FChannelState <> chsHandshake then
    begin
        Result := inherited;
        Exit;
    end;

    Result := True;
    DoHandshakeProcess;
end;

procedure TSChannelWSocket.TriggerDataSent(Error: Word);
begin
  if FChannelState <> chsShutdown then
      inherited
  else
      inherited ShutDown(FShutdownHow);
end;

// TWSocket.ASyncReceive finishes when there's no data in socket but we could
// still have something already decrypted in internal buffer. Make sure we
// consume it all
procedure TSChannelWSocket.TriggerSessionClosed(Error: Word);
begin
    try
        while FDecrBuffer.DataLen > 0 do
            if not TriggerDataAvailable(0) then
                Break;

        inherited;
    except
        on E:Exception do
            HandleBackGroundException(E, 'TSChannelWSocket.TriggerSessionClosed');
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
    pCurrBuffer: TWSocketData;
begin
    // Read next chunk from server
    if FHandShakeData.Stage = hssReadSrvHello then
    begin
        // For some mysterious reason DoRecv requires "var"...
        pCurrBuffer := (PByte(FHandShakeData.IoBuffer) + FHandShakeData.cbIoBuffer);
        cbData := DoRecv(pCurrBuffer,
            Length(FHandShakeData.IoBuffer) - FHandShakeData.cbIoBuffer, 0);
        if cbData <= 0 then // should not happen
            raise ESSPIError.CreateWinAPI('Handshake - no data received or error receiving', 'Recv', WSocket_WSAGetLastError);
        SChannelLog(loSslDevel, Format('Handshake - %d bytes received', [cbData]));
        Inc(FHandShakeData.cbIoBuffer, cbData);
    end;

    // Decode hello
    try
        DoClientHandshake(FSessionData, FHandShakeData);

        // Send token if needed
        if FHandShakeData.Stage in [hssReadSrvHelloContNeed, hssReadSrvHelloOK] then
        begin
            if (FHandShakeData.OutBuffers[0].cbBuffer > 0) and (FHandShakeData.OutBuffers[0].pvBuffer <> nil) then
            begin
                cbData := Send(FHandShakeData.OutBuffers[0].pvBuffer, FHandShakeData.OutBuffers[0].cbBuffer);
                if cbData = FHandShakeData.OutBuffers[0].cbBuffer then
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
                TriggerSessionConnected(0);
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
    CheckServerCert(FSessionData, FhContext);
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
            FShutdownHow := How;
            Send(OutBuffer.pvBuffer, OutBuffer.cbBuffer);
            g_pSSPI.FreeContextBuffer(OutBuffer.pvBuffer);
        end;
    // Just log an exception, don't let it go
    except on E: Exception do
        SChannelLog(loSslErr, E.Message);
    end;
end;

end.
