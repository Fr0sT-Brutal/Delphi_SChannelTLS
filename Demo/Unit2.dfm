object Form2: TForm2
  Left = 0
  Top = 0
  Caption = 'TLS test'
  ClientHeight = 734
  ClientWidth = 646
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
    646
    734)
  PixelsPerInch = 120
  TextHeight = 16
  object lblProgress: TLabel
    Left = 146
    Top = 43
    Width = 4
    Height = 16
  end
  object lblTraf: TLabel
    Left = 384
    Top = 36
    Width = 4
    Height = 16
  end
  object lbl: TLabel
    Left = 10
    Top = 36
    Width = 149
    Height = 16
    Caption = 'Request (default if empty)'
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
    Left = 16
    Top = 335
    Width = 615
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
    Left = 10
    Top = 62
    Width = 368
    Height = 185
    ScrollBars = ssVertical
    TabOrder = 3
    WordWrap = False
  end
  object chbDumps: TCheckBox
    Left = 384
    Top = 66
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
    Left = 384
    Top = 89
    Width = 227
    Height = 17
    Caption = 'Print data'
    TabOrder = 6
    OnClick = chbDataClick
  end
  object Memo1: TMemo
    Left = 384
    Top = 116
    Width = 254
    Height = 131
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
end
