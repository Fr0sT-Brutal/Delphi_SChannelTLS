unit Unit2;

interface

{$DEFINE ICS}

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants, System.Classes,
  Vcl.Graphics, Vcl.Controls, Vcl.Forms, Vcl.Dialogs, Vcl.StdCtrls, WinSock,
  Vcl.ExtCtrls, StrUtils, Vcl.CheckLst, TypInfo,
  JwaWinError, JwaSspi, JwaWinCrypt, SChannel.Utils,
  {$IFDEF ICS}
  IcsSChannelSocket, OverbyteIcsWSocket, OverbyteIcsLogger, OverbyteIcsMimeUtils,
  {$ENDIF}
  SChannelSocketRequest;

type

  TForm2 = class(TForm)
    btnReqSync: TButton;
    mLog: TMemo;
    eURL: TEdit;
    lblProgress: TLabel;
    mReq: TMemo;
    chbDumps: TCheckBox;
    lblTraf: TLabel;
    btnReqAsync: TButton;
    lbl: TLabel;
    chbData: TCheckBox;
    Memo1: TMemo;
    chbReuseSessions: TCheckBox;
    chbUseProxy: TCheckBox;
    eProxy: TEdit;
    chbManualCertCheck: TCheckBox;
    lbxIgnoreFlags: TCheckListBox;
    Label1: TLabel;
    chbPrintCert: TCheckBox;
    chbNoCheckCert: TCheckBox;
    procedure FormCreate(Sender: TObject);
    procedure FormClose(Sender: TObject; var Action: TCloseAction);
    procedure btnReqSyncClick(Sender: TObject);
    procedure btnReqAsyncClick(Sender: TObject);
  private
    SharedSessionCreds: ISharedSessionCreds;
    function GetSharedCreds: ISharedSessionCreds;
    function GetCertCheckIgnoreFlags: TCertCheckIgnoreFlags;
  public
    {$IFDEF ICS}
    icsSock: TSChannelWSocket;
    procedure WSocketBgException(Sender: TObject; E: Exception; var CanClose: Boolean);
    procedure WSocketDataAvailable(Sender: TObject; ErrCode: Word);
    procedure WSocketSessionConnected(Sender: TObject; ErrCode: Word);
    procedure IcsLoggerLogEvent(Sender: TObject; LogOption: TLogOption; const Msg: string);
    procedure WSocketDataSent(Sender: TObject; ErrCode: Word);
    procedure WSocketException(Sender: TObject; SocExcept: ESocketException);
    procedure WSocketSessionClosed(Sender: TObject; ErrCode: Word);
    procedure WSocketTLSDone(Sender: TObject);
    {$ENDIF}
    procedure Log(const s: string; AddStamp: Boolean); overload;
    procedure Log(const s: string); overload;
  end;

var
  Form2: TForm2;
  hClientCreds: CredHandle = ();
  PrintDumps: Boolean = False;
  PrintData: Boolean = False;
  PrintCerts: Boolean = False;
  ManualCertCheck: Boolean = False;

const
  DefaultReq = 'HEAD / HTTP/1.1'+sLineBreak+'Connection: close'+sLineBreak+sLineBreak;

implementation

{$R *.dfm}

procedure TForm2.FormCreate(Sender: TObject);
var IgnFlag: TCertCheckIgnoreFlag;
begin
  if mReq.Lines.Count = 0 then
    mReq.Text := DefaultReq;
  for IgnFlag := Low(TCertCheckIgnoreFlag) to High(TCertCheckIgnoreFlag) do
    lbxIgnoreFlags.Items.Add(GetEnumName(TypeInfo(TCertCheckIgnoreFlag), Ord(IgnFlag)));
end;

procedure TForm2.FormClose(Sender: TObject; var Action: TCloseAction);
begin
  SChannelSocketRequest.SharedSessionCreds := nil;
  SharedSessionCreds := nil;
  SChannel.Utils.Fin;
end;

procedure TForm2.Log(const s: string; AddStamp: Boolean);
begin
  mLog.Lines.Add(IfThen(AddStamp, TimeToStr(Now)+' ')+s);
  if mLog.Lines.Count > 2000 then
  begin
    mLog.Lines.BeginUpdate;
    // Deleting lines one by one is damn slow.
    // So we take length of text and cut half of it
    mLog.SelStart := 0;
    mLog.SelLength := mLog.GetTextLen div 2;
    mLog.SelText := '';
    // Remove probably partial line
    mLog.Lines.Delete(0);
    mLog.Lines.EndUpdate;
  end;
end;

procedure TForm2.Log(const s: string);
begin
  Log(s, True);
end;

function TForm2.GetSharedCreds: ISharedSessionCreds;
begin
  if chbReuseSessions.Checked then
    if SharedSessionCreds = nil then
      SharedSessionCreds := CreateSharedCreds
    else
  else
    SharedSessionCreds := nil;
  Result := SharedSessionCreds;
end;

function TForm2.GetCertCheckIgnoreFlags: TCertCheckIgnoreFlags;
var i: Integer;
begin
  Result := [];
  for i := 0 to lbxIgnoreFlags.Items.Count - 1 do
    if lbxIgnoreFlags.Checked[i] then
      Include(Result, TCertCheckIgnoreFlag(i));
end;

const
  SLblBtnSync: array[Boolean] of string = ('Request sync', 'Cancel');
  SLblBtnAsync: array[Boolean] of string = ('Request async', 'Cancel');

procedure TForm2.btnReqSyncClick(Sender: TObject);
begin
  // Cancel
  if TButton(Sender).Caption = SLblBtnSync[True] then
  begin
    SChannelSocketRequest.Cancel := True;
    TButton(Sender).Caption := SLblBtnSync[False];
    Exit;
  end;

  // Connect
  if TButton(Sender).Caption = SLblBtnSync[False] then
  begin
    SChannelSocketRequest.Cancel := False;
    TButton(Sender).Caption := SLblBtnSync[True];
    SChannelSocketRequest.PrintDumps := chbDumps.Checked;
    SChannelSocketRequest.PrintData := chbData.Checked;
    SChannelSocketRequest.PrintCerts := chbPrintCert.Checked;
    SChannelSocketRequest.ManualCertCheck := chbManualCertCheck.Checked;
    SChannelSocketRequest.CertCheckIgnoreFlags := GetCertCheckIgnoreFlags;

    SChannel.Utils.Init;
    SChannelSocketRequest.LogFn := Self.Log;
    SChannelSocketRequest.SharedSessionCreds := GetSharedCreds;

    Request(eURL.Text, IfThen(mReq.Lines.Count > 0, mReq.Text, DefaultReq));

    SChannelSocketRequest.Cancel := False;
    SChannelSocketRequest.SharedSessionCreds := nil; // important to nil all refs before SChannel.Utils.Fin is called
    TButton(Sender).Caption := SLblBtnSync[False];
  end;
end;

procedure TForm2.btnReqAsyncClick(Sender: TObject);
var
  SessionData: TSessionData;
begin
  {$IFDEF ICS}
  // Cancel
  if TButton(Sender).Caption = SLblBtnAsync[True] then
  begin
    if icsSock <> nil then
      icsSock.Close;
    TButton(Sender).Caption := SLblBtnAsync[False];
    Exit;
  end;

  // Connect
  if TButton(Sender).Caption = SLblBtnAsync[False] then
  begin
    TButton(Sender).Caption := SLblBtnAsync[True];
    PrintDumps := chbDumps.Checked;
    PrintData := chbData.Checked;
    PrintCerts := chbPrintCert.Checked;
    ManualCertCheck := chbManualCertCheck.Checked;

    icsSock := TSChannelWSocket.Create(Self);
    icsSock.OnBgException := WSocketBgException;
    icsSock.OnDataAvailable := WSocketDataAvailable;
    icsSock.OnSessionConnected := WSocketSessionConnected;
    icsSock.OnDataSent := WSocketDataSent;
    icsSock.onException := WSocketException;
    icsSock.OnSessionClosed := WSocketSessionClosed;
    icsSock.OnTLSDone := WSocketTLSDone;
    icsSock.IcsLogger := TIcsLogger.Create(icsSock);
    icsSock.IcsLogger.LogOptions := LogAllOptDump + [loSslDevel, loDestEvent, loDestFile, loAddStamp];
    icsSock.IcsLogger.LogFileName := 'socket.log';
    icsSock.IcsLogger.OnIcsLogEvent := IcsLoggerLogEvent;
    icsSock.Addr := eURL.Text;
    icsSock.Port := '443';
    icsSock.ComponentOptions := [wsoAsyncDnsLookup{, wsoNoReceiveLoop}];
    if chbUseProxy.Checked then
      icsSock.ProxyURL := eProxy.Text // Feature added in "ICS V8.66 - Part 10"
    else
      icsSock.ProxyURL := '';
    icsSock.Secure := True;
    SessionData := icsSock.SessionData;
    SessionData.SharedCreds := GetSharedCreds;
    if ManualCertCheck
      then SessionData.Flags := SessionData.Flags + [sfNoServerVerify]
      else SessionData.Flags := SessionData.Flags - [sfNoServerVerify];
    SessionData.CertCheckIgnoreFlags := GetCertCheckIgnoreFlags;
    icsSock.SessionData := SessionData;
    icsSock.Connect;
  end;
  {$ENDIF}
end;

{$IFDEF ICS}

procedure TForm2.WSocketBgException(Sender: TObject; E: Exception; var CanClose: Boolean);
begin
  Log('WSocket.BgException ' + E.Message);
  CanClose := True;
end;

procedure TForm2.WSocketDataAvailable(Sender: TObject; ErrCode: Word);
var
  TrashCanBuf  : array [0..1023] of AnsiChar;
  res : Integer;
begin
  res := TWSocket(Sender).Receive(@TrashCanBuf, SizeOf(TrashCanBuf)-1);
  // Could be WSAEWOULDBLOCK
  if res = SOCKET_ERROR then
  begin
    if WSAGetLastError <> WSAEWOULDBLOCK then
      Log(Format('Error reading data from server: %s', [SysErrorMessage(WSAGetLastError)]));
    Exit;
  end;

  TrashCanBuf[res] := #0;
  Log('WSocket.DataAvailable('+IntToStr(ErrCode)+'), got '+IntToStr(res)+
    IfThen(PrintData, sLineBreak+string(PAnsiChar(@TrashCanBuf)))
  );
  Form2.lblTraf.Caption := Format('Traffic: %d total / %d payload', [TSChannelWSocket(Sender).ReadCount, TSChannelWSocket(Sender).PayloadReadCount]);
end;

procedure TForm2.WSocketSessionConnected(Sender: TObject; ErrCode: Word);
var req: string;
begin
  Log('WSocket.SessionConnected');

  req := IfThen(mReq.Lines.Count > 0, mReq.Text, DefaultReq);
  Log('Sending request'+IfThen(PrintData, ':'+sLineBreak+req));

  TWSocket(Sender).SendLine(req);
end;

procedure TForm2.IcsLoggerLogEvent(Sender: TObject; LogOption: TLogOption; const Msg: string);
begin
  Log(Msg, False);
  if Pos('Handshake bug', Msg) <> 0 then
    Memo1.Lines.Add(Msg);
end;

procedure TForm2.WSocketDataSent(Sender: TObject; ErrCode: Word);
begin
  Log('WSocket.DataSent');
end;

procedure TForm2.WSocketException(Sender: TObject; SocExcept: ESocketException);
begin
  Log('WSocket.Exception ' + SocExcept.Message);
end;

procedure TForm2.WSocketSessionClosed(Sender: TObject; ErrCode: Word);
begin
  Log('WSocket.SessionClosed');
  Log(Format('Traffic: %d total / %d payload', [TSChannelWSocket(Sender).ReadCount, TSChannelWSocket(Sender).PayloadReadCount]));
  FreeAndNil(icsSock);
  btnReqAsync.Caption := SLblBtnAsync[False];
end;

type
  TSChannelWSocketHack = class(TSChannelWSocket)
    property hContext: CtxtHandle read FhContext;
  end;

procedure TForm2.WSocketTLSDone(Sender: TObject);
var
  Cert: TBytes;
  Enc: AnsiString;
begin
  Log('WSocket.TLSDone');
  if not PrintCerts then Exit;

  Cert := GetCurrentCert(TSChannelWSocketHack(Sender).hContext);
  Log('Cert data:');
  Enc := Base64Encode(PAnsiChar(Cert), Length(Cert));
  Log(string(Enc));
end;

{$ENDIF}

end.
