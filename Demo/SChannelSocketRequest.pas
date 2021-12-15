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
  PrintCerts: Boolean = False;
  ManualCertCheck: Boolean = False;
  CertCheckIgnoreFlags: TCertCheckIgnoreFlags;
  Cancel: Boolean = False;
  LogFn: TDebugFn;
  SharedSessionCreds: ISharedSessionCreds;

function Request(const URL, ReqStr: string): TReqResult;

implementation

type
  // Elementary socket class
  TSyncSocket = class
    HSocket: TSocket;
    procedure Connect(const Addr: string; Port: Word);
    function Send(Buf: Pointer; BufLen: Integer): Integer;
    function Recv(Buf: Pointer; BufLen: Integer): Integer;
    procedure Close;
  end;

function BinToHex(Buf: Pointer; BufLen: NativeUInt): string;
begin
  SetLength(Result, BufLen*2);
  Classes.BinToHex(PAnsiChar(Buf), PChar(Pointer(Result)), BufLen);
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

{ TSyncSocket }

procedure TSyncSocket.Connect(const Addr: string; Port: Word);
var
  SockAddr: TSockAddr;
  HostEnt: PHostEnt;
begin
  try
    // create socket handle
    HSocket := socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    CheckWSResult(HSocket <> INVALID_SOCKET, 'socket');

    HostEnt := gethostbyname(PAnsiChar(AnsiString(Addr)));
    CheckWSResult(HostEnt <> nil, 'gethostbyname');
    SockAddr := Default(TSockAddr);
    SockAddr.sin_family := PF_INET;
    Move(HostEnt^.h_addr^[0], SockAddr.sin_addr, SizeOf(TInAddr));
    Port := htons(Port); // network byte order, short int
    SockAddr.sin_port := Port;

    CheckWSResult(WinSock.connect(HSocket, SockAddr, SizeOf(TSockAddr)) <> SOCKET_ERROR, 'connect');
  except   // error - close socket
    closesocket(HSocket);
    raise;
  end;
end;

function TSyncSocket.Send(Buf: Pointer; BufLen: Integer): Integer;
begin
  Result := WinSock.send(HSocket, Buf^, BufLen, 0);
  if (Result = SOCKET_ERROR) or (Result = 0) then
    Exit(-WSAGetLastError);
  if PrintDumps then
    LogFn(BinToHex(PAnsiChar(Buf), Result));
end;

function TSyncSocket.Recv(Buf: Pointer; BufLen: Integer): Integer;
begin
  Result := WinSock.recv(HSocket, Buf^, BufLen, 0);
  if (Result = SOCKET_ERROR) and (WSAGetLastError = WSAEWOULDBLOCK) then
    Exit(0);
  if Result = SOCKET_ERROR then
    Exit(-WSAGetLastError);
  if (Result > 0) and PrintDumps then
    LogFn(BinToHex(PAnsiChar(Buf), Result));
end;

procedure TSyncSocket.Close;
begin
  closesocket(HSocket);
  HSocket := 0;
end;

function Request(const URL, ReqStr: string): TReqResult;
var
  pCreds: PSessionCreds;
  WSAData: TWSAData;
  HostAddr : TInAddr;
  socket: TSyncSocket;
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
  CertCheckRes: TCertCheckResult;
  Cert: TBytes;
begin
  Result := resConnErr; EncrCnt := 0; DecrCnt := 0;
  socket := TSyncSocket.Create;
  try try
    SessionData := Default(TSessionData);
    SessionData.SharedCreds := SharedSessionCreds;
    SessionData.CertCheckIgnoreFlags := CertCheckIgnoreFlags;
    if ManualCertCheck then
      Include(SessionData.Flags, sfNoServerVerify);
    pCreds := GetSessionCredsPtr(SessionData);
    if SecIsNullHandle(pCreds.hCreds) then
    begin
      CreateSessionCreds(pCreds^);
      LogFn('----- ' + S_Msg_CredsInited);
    end
    else
      LogFn('----- Reusing session');

    LogFn('~~~ Checking connect to '+URL);

    CheckWSResult(WSAStartup(MAKEWORD(2,2), WSAData) = 0, 'WSAStartup');

    // check if hostname is an IP
    HostAddr.S_addr := inet_addr(Pointer(AnsiString(URL)));
    // Hostname is IP - don't verify it
    if DWORD(HostAddr.S_addr) <> INADDR_NONE then
    begin
      LogFn(Format(S_Msg_AddrIsIP, [URL]));
      Include(SessionData.Flags, sfNoServerVerify);
    end;

    socket.Connect(URL, 443);
    LogFn('----- Connected, ' + S_Msg_StartingTLS);
    Result := resTLSErr;

    // Perform handshake
    PerformClientHandshake(SessionData, URL, LogFn, socket.Send, socket.Recv, hCtx, ExtraData);

    if PrintCerts then
    begin
      Cert := GetCurrentCert(hCtx);
      LogFn('Cert data:');
      LogFn(BinToHex(Cert, Length(Cert)));
    end;

    if sfNoServerVerify in SessionData.Flags then
    begin
      CertCheckRes := CheckServerCert(hCtx, IfThen(sfNoServerVerify in SessionData.Flags, '', URL)); // don't check host name if sfNoServerVerify is set
      // Print debug messages why the cert appeared valid
      case CertCheckRes of
        ccrTrusted:        LogFn(LogPrefix + S_Msg_CertIsTrusted);
        ccrValidWithFlags: LogFn(LogPrefix + S_Msg_CertIsValidWithFlags);
      end;
    end;
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
    res := socket.Send(Pointer(IoBuffer), cbData);
    if res < Integer(cbData) then
      if res <= 0 then
        raise ESSPIError.CreateWinAPI('sending encrypted request to server', 'send', res)
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
    ioctlsocket(socket.HSocket, FIONBIO, arg);

    repeat
      Application.ProcessMessages;
      if Cancel then
      begin
        LogFn('~~~ Closed by user request');
        socket.Close;
        Break;
      end;

      // get the data
      res := socket.Recv((PByte(IoBuffer) + cbData), cbIoBufferLength - cbData);
      if res < 0 then
      begin
        if (res = 0) and (WSAGetLastError = WSAEWOULDBLOCK) then
        begin
          Sleep(100);
          Continue;
        end;
        raise ESSPIError.CreateWinAPI('reading data from server', 'recv', res);
      end
      else // success / disconnect
      begin
        if res = 0 then   // Server disconnected.
        begin
          socket.Close;
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
              socket.Close;
              Break;
            end;
          end;
        SEC_I_RENEGOTIATE:
          begin
            LogFn(S_Msg_Renegotiate);
            PerformClientHandshake(SessionData, URL, LogFn, socket.Send, socket.Recv, hCtx, ExtraData);
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
    socket.Close;
    FreeAndNil(socket);
    DeleteContext(hCtx);
    LogFn('----- Begin Cleanup');
    FinSession(SessionData);
    LogFn('----- All Done -----');
  end;
end;

end.
