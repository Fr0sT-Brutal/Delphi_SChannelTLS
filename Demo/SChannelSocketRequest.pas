{
  Demo unit of TLS request by means of WinAPI SChannel

  (c) Fr0sT-Brutal
  License MIT
}

unit SChannelSocketRequest;

interface

uses
  Forms, Winapi.Windows, System.SysUtils, WinSock, Classes, StrUtils,
  JwaWinError, JwaSspi, SChannel.Utils, SChannel.SyncHandshake;

type
  TReqResult = (resConnErr, resTLSErr, resOK);

var
  PrintDumps: Boolean = False;
  PrintData: Boolean = False;
  Cancel: Boolean = False;
  LogFn: TLogFn;

function Request(const URL, ReqStr: string): TReqResult;

implementation

function BinToHex(Buf: Pointer; BufLen: NativeUInt): string;
begin
  SetLength(Result, BufLen*2);
  Classes.BinToHex(PAnsiChar(Buf), PChar(Pointer(Result)), BufLen);
end;

function SendFn(Data: Pointer; Buf: Pointer; BufLen: Integer): Integer;
begin
  Result := send(TSocket(Data), Buf^, BufLen, 0);
  if (Result = SOCKET_ERROR) or (Result = 0) then
    raise ESSPIError.CreateWinAPI('Error sending data to server', 'send', WSAGetLastError);
  if PrintDumps then
    LogFn(BinToHex(PAnsiChar(Buf), Result));
end;

function RecvFn(Data: Pointer; Buf: Pointer; BufLen: Integer): Integer;
begin
  Result := recv(TSocket(Data), Buf^, BufLen, 0);
  if Result = SOCKET_ERROR then
    raise ESSPIError.CreateWinAPI('Error reading data from server', 'recv', WSAGetLastError);
  if Result = 0 then
    raise ESSPIError.Create('Server unexpectedly disconnected');
  if PrintDumps then
    LogFn(BinToHex(PAnsiChar(Buf), Result));
end;

procedure CheckWSResult(Res: Boolean; const Method: string);
const
  SFullErrorMsg = '#%d %s (API method "%s")';
  SShortErrorMsg = '#%d %s';
begin
  if not Res then
    if Method <> ''
      then raise Exception.CreateFmt(SFullErrorMsg, [WSAGetLastError, SysErrorMessage(WSAGetLastError), Method])
      else raise Exception.CreateFmt(SShortErrorMsg, [WSAGetLastError, SysErrorMessage(WSAGetLastError)]);
end;

function ConnectSocket(const Addr: string; Port: Word): TSocket;
var
  SockAddr: TSockAddr;
  HostEnt: PHostEnt;
begin
  Result := INVALID_SOCKET;
  try
    // create socket handle
    Result := socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    CheckWSResult(Result <> INVALID_SOCKET, 'socket');

    HostEnt := gethostbyname(PAnsiChar(AnsiString(Addr)));
    CheckWSResult(HostEnt <> nil, 'gethostbyname');
    SockAddr := Default(TSockAddr);
    SockAddr.sin_family := PF_INET;
    Move(HostEnt^.h_addr^[0], SockAddr.sin_addr, SizeOf(TInAddr));
    Port := htons(Port); // network byte order, short int
    SockAddr.sin_port := Port;

    CheckWSResult(connect(Result, SockAddr, SizeOf(TSockAddr)) <> SOCKET_ERROR, 'connect');
  except   // error - close socket
    closesocket(Result);
    raise;
  end;
end;

function Request(const URL, ReqStr: string): TReqResult;
var
  WSAData: TWSAData;
  sock: TSocket;
  hCtx: CtxtHandle;
  IoBuffer: TBytes;
  cbIoBufferLength: DWORD;
  Sizes: SecPkgContext_StreamSizes;
  req: RawByteString;
  scRet: SECURITY_STATUS;
  cbRead, cbData: DWORD;
  buf, ExtraData: TBytes;
  res: Integer;
  EncrCnt, DecrCnt: Cardinal;
//  OutBuffer: SecBuffer;
  SessionData: TSessionData;
  arg: u_long;
begin
  Result := resConnErr; EncrCnt := 0; DecrCnt := 0; sock := INVALID_SOCKET;
  try try
    SessionData := Default(TSessionData);
    InitSession(SessionData);
    LogFn('----- ' + S_Msg_CredsInited);

    LogFn('~~~ Checking connect to '+URL);

    CheckWSResult(WSAStartup(MAKEWORD(2,2), WSAData) = 0, 'WSAStartup');

    sock := ConnectSocket(URL, 443);
    LogFn('----- Connected, ' + S_Msg_StartingTLS);
    Result := resTLSErr;

    // Perform handshake
    PerformClientHandshake(SessionData, URL, LogFn, Pointer(sock), @SendFn, @RecvFn, hCtx, ExtraData);
    CheckServerCert(hCtx, URL);
    LogFn(LogPrefix + S_Msg_SrvCredsAuth);
    InitBuffers(hCtx, IoBuffer, Sizes);
    cbIoBufferLength := Length(IoBuffer);

    // Build the request - must be < maximum message size
    // message begins after the header
    req := RawByteString(ReqStr);
    EncryptData(hCtx, Sizes, Pointer(req), Length(req), PByte(IoBuffer), cbIoBufferLength, cbData); {}// ? что если больше, за два захода понадобится
    LogFn(Format(S_Msg_Sending, [Length(req), cbData])+
      IfThen(PrintData, sLineBreak+string(req)));

    // Send the encrypted data to the server.
    res := send(sock, Pointer(IoBuffer)^, cbData, 0);
    if res < cbData then
      if (res = SOCKET_ERROR) or (res = 0) then
        raise ESSPIError.CreateWinAPI('Error sending encrypted request to server', 'send', WSAGetLastError)
      else
        raise ESSPIError.Create('Error sending encrypted request to server: partial sent');

    // Receive a Response
    // cbData is the length of received data in IoBuffer
    SetLength(buf, Sizes.cbMaximumMessage);
    cbData := 0; DecrCnt := 0;
    Move(Pointer(ExtraData)^, Pointer(IoBuffer)^, Length(ExtraData));
    Inc(cbData, Length(ExtraData));
    // Set socket non-blocking
    arg := 1;
    ioctlsocket(sock, FIONBIO, arg);

    repeat
      Application.ProcessMessages;
      if Cancel then
      begin
        LogFn('~~~ Closed by user request');
        closesocket(sock);
        Break;
      end;

      // get the data
      res := recv(sock, (PByte(IoBuffer) + cbData)^, cbIoBufferLength - cbData, 0);
      if res = SOCKET_ERROR then
      begin
        if WSAGetLastError = WSAEWOULDBLOCK then
        begin
          Sleep(100);
          Continue;
        end;
        raise ESSPIError.CreateWinAPI('Error reading data from server', 'recv', WSAGetLastError);
      end
      else // success / disconnect
      begin
        if res = 0 then   // Server disconnected.
        begin
          closesocket(sock);
          Break;
        end;
        LogFn(Format('%d bytes of encrypted application data received', [res]));
        Inc(cbData, res);
        Inc(EncrCnt, res);
      end;

      scRet := DecryptData(hCtx, Sizes, PByte(IoBuffer), cbData, PByte(buf), Length(buf), cbRead);
      case scRet of
        SEC_E_OK, SEC_E_INCOMPLETE_MESSAGE, SEC_I_CONTEXT_EXPIRED:
          begin
            buf[cbRead] := 0;
            if cbRead = 0 then
              LogFn('No data')
            else
              LogFn('Received '+IntToStr(cbRead)+' bytes'+
                IfThen(PrintData, sLineBreak+string(StrPas(PAnsiChar(buf)))));
            Inc(DecrCnt, cbRead);
            if scRet = SEC_I_CONTEXT_EXPIRED then
            begin
              LogFn('SEC_I_CONTEXT_EXPIRED');
              closesocket(sock);
              Break;
            end;
          end;
        SEC_I_RENEGOTIATE:
          begin
            LogFn(S_Msg_Renegotiate);
            PerformClientHandshake(SessionData, URL, LogFn, Pointer(sock), @SendFn, @RecvFn, hCtx, ExtraData);
            cbData := 0;
            Move(Pointer(ExtraData)^, Pointer(IoBuffer)^, Length(ExtraData));
            Inc(cbData, Length(ExtraData));
          end;
      end; // case

    until False;

{}{
      // Send a close_notify alert to the server and close down the connection.
      GetShutdownData(SessionData, hCtx, OutBuffer);
      if OutBuffer.cbBuffer > 0 then
      begin
        LogFn(Format('Sending close notify - %d bytes of data', [OutBuffer.cbBuffer]));
        sock.Send(OutBuffer.pvBuffer, OutBuffer.cbBuffer);
        g_pSSPI.FreeContextBuffer(OutBuffer.pvBuffer); // Free output buffer.
      end;
}
    LogFn('----- Disconnected From Server');
    Result := resOK;
  except on E: Exception do
    LogFn(E.Message);
  end;
  finally
    LogFn(Format('~~~ Traffic: %d total / %d payload', [EncrCnt, DecrCnt]));
    closesocket(sock);
    DeleteContext(hCtx);
    LogFn('----- Begin Cleanup');
    FinSession(SessionData);
    LogFn('----- All Done -----');
  end;
end;


end.
