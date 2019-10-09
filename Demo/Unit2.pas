unit Unit2;

interface

{$DEFINE ICS}

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants, System.Classes,
  Vcl.Graphics, Vcl.Controls, Vcl.Forms, Vcl.Dialogs, Vcl.StdCtrls, WinSock,
  Vcl.ExtCtrls, StrUtils,
  JwaWinError, JwaSspi, SChannel.Utils,
  {$IFDEF ICS}
  IcsSChannelSocket, OverbyteIcsWSocket, OverbyteIcsLogger,
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
    procedure chbDumpsClick(Sender: TObject);
    procedure btnReqSyncClick(Sender: TObject);
    procedure btnReqAsyncClick(Sender: TObject);
    procedure FormCreate(Sender: TObject);
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
    {$ENDIF}
    procedure Log(const s: string; AddStamp: Boolean); overload;
    procedure Log(const s: string); overload;
  end;

var
  Form2: TForm2;
  hClientCreds: CredHandle = ();
  PrintDumps: Boolean = False;

const
  DefaultReq = 'HEAD / HTTP/1.1'+sLineBreak+'Connection: close'+sLineBreak+sLineBreak;

implementation

{$R *.dfm}

procedure TForm2.FormCreate(Sender: TObject);
begin
  mReq.Text := DefaultReq;
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

const
  SLblBtnSync: array[Boolean] of string = ('Request sync', 'Cancel');
  SLblBtnAsync: array[Boolean] of string = ('Request async', 'Cancel');

procedure TForm2.btnReqSyncClick(Sender: TObject);
begin
  // Cancel
  if TButton(Sender).Caption = SLblBtnSync[True] then
  begin
    Cancel := True;
    SChannelSocketRequest.Cancel := True;
    TButton(Sender).Caption := SLblBtnSync[False];
    Exit;
  end;

  // Connect
  if TButton(Sender).Caption = SLblBtnSync[False] then
  begin
    Cancel := False;
    SChannelSocketRequest.Cancel := False;
    TButton(Sender).Caption := SLblBtnSync[True];
    SChannel.Utils.Init;
    SChannelSocketRequest.LogFn := Self.Log;
    try
      Request(eURL.Text, IfThen(mReq.Lines.Count > 0, mReq.Text, DefaultReq));
    finally
      SChannel.Utils.Fin;
    end;
    Cancel := False;
    SChannelSocketRequest.Cancel := False;
    TButton(Sender).Caption := SLblBtnSync[False];
    Exit;
  end;
end;

procedure TForm2.chbDumpsClick(Sender: TObject);
begin
  PrintDumps := TCheckBox(Sender).Checked;
  SChannelSocketRequest.PrintDumps := PrintDumps;
end;

procedure TForm2.btnReqAsyncClick(Sender: TObject);
begin
  {$IFDEF ICS}
  icsSock := TSChannelWSocket.Create(Self);
  icsSock.OnBgException := WSocketBgException;
  icsSock.OnDataAvailable := WSocketDataAvailable;
  icsSock.OnSessionConnected := WSocketSessionConnected;
  icsSock.OnDataSent := WSocketDataSent;
  icsSock.onException := WSocketException;
  icsSock.OnSessionClosed := WSocketSessionClosed;
  icsSock.IcsLogger := TIcsLogger.Create(icsSock);
  icsSock.IcsLogger.LogOptions := LogAllOptDump + [loSslDevel, loDestEvent, loDestFile, loAddStamp];
  icsSock.IcsLogger.LogFileName := 'socket.log';
  icsSock.IcsLogger.OnIcsLogEvent := IcsLoggerLogEvent;
  icsSock.Addr := eURL.Text;
  icsSock.Port := '443';
  icsSock.ComponentOptions := [wsoAsyncDnsLookup, wsoNoReceiveLoop];
  icsSock.Secure := True;
  icsSock.Connect;
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
  if res = SOCKET_ERROR then
  begin
    Log(Format('Error reading data from server: %s', [SysErrorMessage(WSAGetLastError)]));
    TSChannelWSocket(Sender).Close;
    Exit;
  end;

  TrashCanBuf[res] := #0;
  Log('WSocket.DataAvailable, got '+IntToStr(res)+sLineBreak+StrPas(PAnsiChar(@TrashCanBuf)));
  Form2.lblTraf.Caption := Format('Traffic: %d total / %d payload', [TSChannelWSocket(Sender).ReadCount, TSChannelWSocket(Sender).PayloadReadCount]);
end;

procedure TForm2.WSocketSessionConnected(Sender: TObject; ErrCode: Word);
var req: string;
begin
  Log('WSocket.SessionConnected');

  req := IfThen(mReq.Lines.Count > 0, mReq.Text, DefaultReq);
  Log('Sending request:'+sLineBreak+req);

  TWSocket(Sender).SendLine(req);
end;

procedure TForm2.IcsLoggerLogEvent(Sender: TObject; LogOption: TLogOption; const Msg: string);
begin
  Log(Msg, False);
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
end;

{$ENDIF}

end.
