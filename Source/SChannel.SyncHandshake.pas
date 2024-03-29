{
  Helper function that implements synchronous TLS handshake by means of
  Windows SChannel.
  The function is transport-agnostic so it could be applied to any socket
  implementation or even other transport.

  Inspired by [TLS-Sample](http://www.coastrd.com/c-schannel-smtp)

  Uses [JEDI API units](https://jedi-apilib.sourceforge.net)

  (c) Fr0sT-Brutal
  
  License MIT
}

unit SChannel.SyncHandshake;

interface
{$IFDEF MSWINDOWS}

uses
  Windows, SysUtils,
  SChannel.JwaBaseTypes, SChannel.JwaWinError, SChannel.JwaWinCrypt,
  SChannel.JwaSspi, SChannel.JwaSChannel,
  SChannel.Utils;

type
  // Synchronous communication method.
  //   @param Buf - buffer with data
  //   @param BufLen - size of data in buffer
  // @returns amount of data sent if >= 0 or error code if < 0. \
  //   Error code is used to log and create exception. FormatMessage is used to \
  //   generate a string from error code. \
  //   Must try to send all data in full, as no retries or repeated sends is done.
  // @raises exception on some non-network error
  TSendFn = function (Buf: Pointer; BufLen: Integer): Integer of object;
  // Synchronous communication method.
  //   @param Buf - buffer to receive data
  //   @param BufLen - size of free space in buffer
  // @returns amount of data received if >= 0 or error code if < 0. \
  //   Error code is used to log and create exception. FormatMessage is used to \
  //   generate a string from error code. \
  //   Could receive only some of the data available as incomplete packet is \
  //   read in loop
  // @raises exception on some non-network error
  TRecvFn = function (Buf: Pointer; BufLen: Integer): Integer of object;

  // Specific exception class raised by PerformClientHandshake on communication failures.
  // Just to distinguish SChannel-level errors from recv/send failures
  EHandshakeCommError = class(Exception)
  public
    ErrCode: DWORD;
  end;

// Synchronously perform full handshake process including communication with server.
procedure PerformClientHandshake(var SessionData: TSessionData; const ServerName: string;
  DebugLogFn: TDebugFn; SendFn: TSendFn; RecvFn: TRecvFn;
  out hContext: CtxtHandle; out ExtraData: TBytes);

{$ENDIF MSWINDOWS}

implementation
{$IFDEF MSWINDOWS}

// ~~ Utils ~~

function CommError(ErrCode: DWORD; const Msg: string): EHandshakeCommError;
begin
  if ErrCode <> 0
    then Result := EHandshakeCommError.CreateFmt(Msg, [ErrCode, SysErrorMessage(ErrCode)])
    else Result := EHandshakeCommError.Create(Msg);
  Result.ErrCode := ErrCode;
end;

// Synchronously perform full handshake process including communication with server.
// Communication is done via two callback functions.
//   @param SessionData - [IN/OUT] record with session data
//   @param ServerName - name of domain to connect to
//   @param DebugLogFn - logging callback, could be @nil
//   @param Data - any data with which `SendFn` and `RecvFn` will be called
//   @param SendFn - data send callback
//   @param RecvFn - data read callback
//   @param hContext - [OUT] receives current session context
//   @param ExtraData - [OUT] receives extra data sent by server to be decrypted
// @raises ESSPIError on SChannel-related failure,
//         EHandshakeCommError on communication failure
procedure PerformClientHandshake(var SessionData: TSessionData; const ServerName: string;
  DebugLogFn: TDebugFn; SendFn: TSendFn; RecvFn: TRecvFn;
  out hContext: CtxtHandle; out ExtraData: TBytes);
var
  HandShakeData: THandShakeData;
  cbData: Integer;
  HandshakeBug: Boolean;

  procedure DoHandshakeStart;
  begin
    // Generate hello
    DoClientHandshake(SessionData, HandShakeData, DebugLogFn);
    Assert(HandShakeData.Stage = hssSendCliHello);

    // Send hello to server
    cbData := SendFn(HandShakeData.OutBuffers[0].pvBuffer, HandShakeData.OutBuffers[0].cbBuffer);
    if cbData <> Integer(HandShakeData.OutBuffers[0].cbBuffer) then
      if cbData < 0
        then raise CommError(Abs(cbData), S_Msg_HShStageW1Fail)
        else raise CommError(0, S_Msg_HShStageW1Incomplete);
    Debug(DebugLogFn, Format(S_Msg_HShStageW1Success, [cbData]));
    g_pSSPI.FreeContextBuffer(HandShakeData.OutBuffers[0].pvBuffer); // Free output buffer.
    SetLength(HandShakeData.OutBuffers, 0);
    HandShakeData.Stage := hssReadSrvHello;
  end;

begin
  HandShakeData := Default(THandShakeData);
  SessionData.ServerName := ServerName;
  hContext := Default(CtxtHandle);
  HandshakeBug := False;

  try try
    DoHandshakeStart;
    // Read hello from server
    SetLength(HandShakeData.IoBuffer, IO_BUFFER_SIZE);
    HandShakeData.cbIoBuffer := 0;
    // Read response until it is complete
    repeat
      if HandShakeData.Stage = hssReadSrvHello then
      begin
        cbData := RecvFn((PByte(HandShakeData.IoBuffer) + HandShakeData.cbIoBuffer),
          Length(HandShakeData.IoBuffer) - HandShakeData.cbIoBuffer);
        if cbData <= 0 then
          raise CommError(Abs(cbData), S_Msg_HShStageRFail);
        Debug(DebugLogFn, Format(S_Msg_HShStageRSuccess, [cbData]));
        Inc(HandShakeData.cbIoBuffer, cbData);
      end;

      // Decode hello
      try
        DoClientHandshake(SessionData, HandShakeData, DebugLogFn);
      except on E: ESSPIError do
        // Hide Windows handshake bug and restart the process for the first time
        if (HandShakeData.Stage = hssReadSrvHello) and IsWinHandshakeBug(E.SecStatus)
          and not HandshakeBug then
        begin
          Debug(DebugLogFn, Format(S_Msg_HandshakeBug, [E.Message]));
          HandshakeBug := True;
          DeleteContext(HandShakeData.hContext);
          HandShakeData.Stage := hssNotStarted;
          DoHandshakeStart;
          Continue;
        end
        else
          raise;
      end;
      // Send token if needed
      if HandShakeData.Stage in [hssReadSrvHelloContNeed, hssReadSrvHelloOK] then
      begin
        if (HandShakeData.OutBuffers[0].cbBuffer > 0) and (HandShakeData.OutBuffers[0].pvBuffer <> nil) then
        begin
          cbData := SendFn(HandShakeData.OutBuffers[0].pvBuffer, HandShakeData.OutBuffers[0].cbBuffer);
          if cbData <> Integer(HandShakeData.OutBuffers[0].cbBuffer) then
            if cbData < 0
              then raise CommError(Abs(cbData), S_Msg_HShStageW2Fail)
              else raise CommError(0, S_Msg_HShStageW2Incomplete);
          Debug(DebugLogFn, Format(S_Msg_HShStageW2Success, [cbData]));
          g_pSSPI.FreeContextBuffer(HandShakeData.OutBuffers[0].pvBuffer); // Free output buffer
          SetLength(HandShakeData.OutBuffers, 0);
        end;

        if HandShakeData.Stage = hssReadSrvHelloContNeed then
        begin
          HandShakeData.Stage := hssReadSrvHello;
          Continue;
        end
        else if HandShakeData.Stage = hssReadSrvHelloOK then
        begin
          if HandShakeData.cbIoBuffer > 0 then
            Debug(DebugLogFn, Format(S_Msg_HShExtraData, [HandShakeData.cbIoBuffer]));
          Debug(DebugLogFn, S_Msg_Established);
          HandShakeData.Stage := hssDone; // useless
          // Return extra data if any received. 0-length will work as well
          ExtraData := Copy(HandShakeData.IoBuffer, 0, HandShakeData.cbIoBuffer);
          Break;
        end;
      end;

    until False;
  except
    begin
      // Delete the security context in the case of a fatal error.
      DeleteContext(HandShakeData.hContext);
      raise;
    end;
  end;
  finally
    begin
      if Length(HandShakeData.OutBuffers) > 0 then
        g_pSSPI.FreeContextBuffer(HandShakeData.OutBuffers[0].pvBuffer); // Free output buffer
      SetLength(HandShakeData.OutBuffers, 0);
      hContext := HandShakeData.hContext;
    end;
  end;
end;

{$ENDIF MSWINDOWS}
end.
