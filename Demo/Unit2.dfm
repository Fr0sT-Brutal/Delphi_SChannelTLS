object Form2: TForm2
  Left = 0
  Top = 0
  Caption = 'TLS test'
  ClientHeight = 734
  ClientWidth = 704
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -13
  Font.Name = 'Tahoma'
  Font.Style = []
  OldCreateOrder = False
  OnClose = FormClose
  OnCreate = FormCreate
  DesignSize = (
    704
    734)
  PixelsPerInch = 120
  TextHeight = 16
  object lblProgress: TLabel
    Left = 144
    Top = 125
    Width = 4
    Height = 16
  end
  object lblTraf: TLabel
    Left = 382
    Top = 118
    Width = 4
    Height = 16
  end
  object lbl: TLabel
    Left = 8
    Top = 147
    Width = 149
    Height = 16
    Caption = 'Request (default if empty)'
  end
  object Label1: TLabel
    Left = 504
    Top = 64
    Width = 42
    Height = 16
    Caption = 'Ignore:'
  end
  object btnReqSync: TButton
    Left = 272
    Top = 8
    Width = 106
    Height = 26
    Caption = 'Request sync'
    Default = True
    TabOrder = 0
    OnClick = btnReqSyncClick
  end
  object mLog: TMemo
    Left = 8
    Top = 335
    Width = 688
    Height = 391
    Anchors = [akLeft, akTop, akRight, akBottom]
    ScrollBars = ssVertical
    TabOrder = 1
  end
  object eURL: TEdit
    Left = 8
    Top = 8
    Width = 241
    Height = 24
    TabOrder = 2
    Text = 'google.com'
  end
  object mReq: TMemo
    Left = 8
    Top = 171
    Width = 368
    Height = 158
    ScrollBars = ssVertical
    TabOrder = 3
    WordWrap = False
  end
  object chbDumps: TCheckBox
    Left = 382
    Top = 148
    Width = 227
    Height = 17
    Caption = 'Print handshake dumps (sync only)'
    TabOrder = 4
    OnClick = chbDumpsClick
  end
  object btnReqAsync: TButton
    Left = 384
    Top = 8
    Width = 105
    Height = 26
    Caption = 'Request async'
    TabOrder = 5
    OnClick = btnReqAsyncClick
  end
  object chbData: TCheckBox
    Left = 382
    Top = 171
    Width = 227
    Height = 17
    Caption = 'Print data'
    TabOrder = 6
    OnClick = chbDataClick
  end
  object Memo1: TMemo
    Left = 382
    Top = 224
    Width = 256
    Height = 105
    ScrollBars = ssVertical
    TabOrder = 7
    WordWrap = False
  end
  object chbReuseSessions: TCheckBox
    Left = 504
    Top = 12
    Width = 121
    Height = 17
    Caption = 'Reuse sessions'
    TabOrder = 8
  end
  object chbUseProxy: TCheckBox
    Left = 16
    Top = 40
    Width = 81
    Height = 17
    Caption = 'Use proxy'
    TabOrder = 9
  end
  object eProxy: TEdit
    Left = 31
    Top = 63
    Width = 218
    Height = 24
    TabOrder = 10
    TextHint = '(socks5|http)://host:port'
  end
  object chbManualCertCheck: TCheckBox
    Left = 504
    Top = 32
    Width = 134
    Height = 17
    Caption = 'Check cert manually'
    TabOrder = 11
  end
  object lbxIgnoreFlags: TCheckListBox
    Left = 560
    Top = 55
    Width = 134
    Height = 87
    TabOrder = 12
  end
  object chbPrintCert: TCheckBox
    Left = 382
    Top = 194
    Width = 227
    Height = 17
    Caption = 'Print cert data (async only)'
    TabOrder = 13
    OnClick = chbDataClick
  end
  object chbNoCheckCert: TCheckBox
    Left = 504
    Top = 117
    Width = 134
    Height = 17
    Caption = 'Don'#39't check cert'
    TabOrder = 14
    Visible = False
  end
end
