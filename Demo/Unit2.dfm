object Form2: TForm2
  Left = 0
  Top = 0
  Caption = 'TLS test'
  ClientHeight = 734
  ClientWidth = 652
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -13
  Font.Name = 'Tahoma'
  Font.Style = []
  OldCreateOrder = False
  OnCreate = FormCreate
  DesignSize = (
    652
    734)
  PixelsPerInch = 120
  TextHeight = 16
  object lblProgress: TLabel
    Left = 152
    Top = 47
    Width = 4
    Height = 16
  end
  object lblTraf: TLabel
    Left = 390
    Top = 66
    Width = 65
    Height = 17
  end
  object lbl: TLabel
    Left = 16
    Top = 40
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
    Top = 264
    Width = 621
    Height = 462
    Anchors = [akLeft, akTop, akRight, akBottom]
    ScrollBars = ssVertical
    TabOrder = 1
  end
  object eURL: TEdit
    Left = 16
    Top = 8
    Width = 241
    Height = 24
    TabOrder = 2
    Text = 'google.com'
  end
  object mReq: TMemo
    Left = 16
    Top = 66
    Width = 368
    Height = 185
    ScrollBars = ssVertical
    TabOrder = 3
    WordWrap = False
  end
  object chbDumps: TCheckBox
    Left = 390
    Top = 43
    Width = 161
    Height = 17
    Caption = 'Print handshake dumps'
    TabOrder = 4
    OnClick = chbDumpsClick
  end
  object btnReqAsync: TButton
    Left = 384
    Top = 8
    Width = 105
    Height = 26
    Caption = 'Request async'
    Default = True
    TabOrder = 5
    OnClick = btnReqAsyncClick
  end
end
