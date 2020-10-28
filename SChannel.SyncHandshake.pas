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
  JwaBaseTypes, JwaWinError, JwaWinCrypt, JwaSspi, JwaSChannel,
  SChannel.Utils;

type
  // Logging function. All messages coming from functions of this unit are
  // prefixed with `SChannel.Utils.LogPrefix` constant
  TLogFn = procedure (const Msg: string) of object;
  // Synchronous communication function.
  //   @param Data - the value of `Data` with which `PerformClientHandshake` was called \
  //     (Socket object, handle, etc)
  //   @param Buf - buffer with data
  //   @param BufLen - size of data in buffer
  // @returns amount of data sent. Must try to send all data in full, as no \
  //   retries or repeated sends is done.
  // @raises exception on error
  TSendFn = function (Data: Pointer; Buf: Pointer; BufLen: Integer): Integer;
  // Synchronous communication function.
  //   @param Data - the value of `Data` with which `PerformClientHandshake` was called \
  //     (Socket object, handle, etc)
  //   @param Buf - buffer to receive data
  //   @param BufLen - size of free space in buffer
  // @returns amount of data read, `0` if no data read and `-1` on error.\
  //   Must try to send all data in full, as no retries or repeated sends is done.
  // @raises exception on error
  TRecvFn = function (Data: Pointer; Buf: Pointer; BufLen: Integer): Integer;

// Synchronously perform full handshake process including communication with server.
procedure PerformClientHandshake(var SessionData: TSessionData; const ServerName: string;
  LogFn: TLogFn; Data: Pointer; SendFn: TSendFn; RecvFn: TRecvFn;
  out hContext: CtxtHandle; out ExtraData: TBytes);

{$ENDIF MSWINDOWS}

implementation
{$IFDEF MSWINDOWS}

// ~~ Utils ~~

// Empty default logging function - to avoid if Assigned checks
type
  TLogFnHoster = class
    class procedure DefLogFn(const Msg: string);
  end;

class procedure TLogFnHoster.DefLogFn(const Msg: string);
begin
end;

// Synchronously perform full handshake process including communication with server.
// Communication is done via two callback functions.
//   @param SessionData - [IN/OUT] record with session data
//   @param ServerName - name of domain to connect to
//   @param LogFn - logging callback, could be @nil
//   @param Data - any data with which `SendFn` and `RecvFn` will be called
//   @param SendFn - data send callback
//   @param RecvFn - data read callback
//   @param hContext - [OUT] receives current session context
//   @param ExtraData - [OUT] receives extra data sent by server to be decrypted
// @raises ESSPIError on error
procedure PerformClientHandshake(var SessionData: TSessionData; const ServerName: string;
  LogFn: TLogFn; Data: Pointer; SendFn: TSendFn; RecvFn: TRecvFn;
  out hContext: CtxtHandle; out ExtraData: TBytes);
var
  HandShakeData: THandShakeData;
  cbData: Integer;
  HandshakeBug: Boolean;

  procedure DoHandshakeStart;
  begin
    // Generate hello
    DoClientHandshake(SessionData, HandShakeData);
    Assert(HandShakeData.Stage = hssSendCliHello);

    // Send hello to server
    cbData := SendFn(Data, HandShakeData.OutBuffers[0].pvBuffer, HandShakeData.OutBuffers[0].cbBuffer);
    if cbData = Integer(HandShakeData.OutBuffers[0].cbBuffer) then
      LogFn(Format(S_Msg_HShStageW1Success, [cbData]))
    else
      LogFn(S_Msg_HShStageW1Fail);
    g_pSSPI.FreeContextBuffer(HandShakeData.OutBuffers[0].pvBuffer); // Free output buffer.
    SetLength(HandShakeData.OutBuffers, 0);
    HandShakeData.Stage := hssReadSrvHello;
  end;

begin
  HandShakeData := Default(THandShakeData);
  HandShakeData.ServerName := ServerName;
  hContext := Default(CtxtHandle);
  HandshakeBug := False;
  if not Assigned(LogFn) then
    LogFn := TLogFnHoster.DefLogFn;

  try try
    DoHandshakeStart;
    // Read hello from server
    SetLength(HandShakeData.IoBuffer, IO_BUFFER_SIZE);
    HandShakeData.cbIoBuffer := 0;
    // Read response until it is complete
    repeat
      if HandShakeData.Stage = hssReadSrvHello then
      begin
        cbData := RecvFn(Data, (PByte(HandShakeData.IoBuffer) + HandShakeData.cbIoBuffer),
          Length(HandShakeData.IoBuffer) - HandShakeData.cbIoBuffer);
        if cbData <= 0 then // should not happen
          raise ESSPIError.Create(S_Msg_HShStageRFail);
        LogFn(Format(S_Msg_HShStageRSuccess, [cbData]));
        Inc(HandShakeData.cbIoBuffer, cbData);
      end;

      // Decode hello
      try
        DoClientHandshake(SessionData, HandShakeData);
      except on E: ESSPIError do
        // Hide Windows handshake bug and restart the process for the first time
        if (HandShakeData.Stage = hssReadSrvHello) and IsWinHandshakeBug(E.SecStatus)
          and not HandshakeBug then
        begin
          LogFn(Format(S_Msg_HandshakeBug, [E.Message]));
          HandshakeBug := True;
          DeleteContext(HandShakeData.hContext);
          HandShakeData.Stage := hssNotStarted;
          DoHandshakeStart;
          Continue;
        end
        else
          raise E;     // TODO: after this exc props are lost
      end;
      // Send token if needed
      if HandShakeData.Stage in [hssReadSrvHelloContNeed, hssReadSrvHelloOK] then
      begin
        if (HandShakeData.OutBuffers[0].cbBuffer > 0) and (HandShakeData.OutBuffers[0].pvBuffer <> nil) then
        begin
          cbData := SendFn(Data, HandShakeData.OutBuffers[0].pvBuffer, HandShakeData.OutBuffers[0].cbBuffer);
          if cbData = Integer(HandShakeData.OutBuffers[0].cbBuffer) then
            LogFn(Format(S_Msg_HShStageW2Success, [cbData]))
          else
            LogFn(S_Msg_HShStageW2Fail);
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
            LogFn(Format(S_Msg_HShExtraData, [HandShakeData.cbIoBuffer]));
          LogFn(S_Msg_Established);
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
