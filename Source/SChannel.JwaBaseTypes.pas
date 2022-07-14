{******************************************************************************}
{                                                                              }
{ Some necessary basic API types missing in WinApi.Windows                     }
{                                                                              }
{******************************************************************************}
unit SChannel.JwaBaseTypes;

interface

uses
  Windows;

type
  {$EXTERNALSYM PWSTR}
  PWSTR = Windows.LPWSTR;

type
  {$EXTERNALSYM LPBYTE}
  LPBYTE      = PByte;
  {$EXTERNALSYM GUID}
  GUID        = TGUID;
  {$EXTERNALSYM PVOID}
  PVOID       = Pointer;
  {$EXTERNALSYM LPVOID}
  LPVOID      = Pointer;
  {$EXTERNALSYM LPLPVOID}
  LPLPVOID    = PPointer;
  {$EXTERNALSYM LPLPSTR}
  LPLPSTR     = PLPSTR;
  {$EXTERNALSYM LPLPWSTR}
  LPLPWSTR    = PLPWSTR;
  {$EXTERNALSYM LPLPCSTR}
  LPLPCSTR    = ^LPCSTR;
  {$EXTERNALSYM LPLPCWSTR}
  LPLPCWSTR   = ^LPCWSTR;
  {$EXTERNALSYM LPLPCTSTR}
  LPLPCTSTR   = ^LPCTSTR;
{$IFNDEF WIN64}
  {$EXTERNALSYM ULONG_PTR}
  ULONG_PTR   = LongWord;
  {$EXTERNALSYM size_t}
  size_t      = LongWord;
{$ELSE}
  {$EXTERNALSYM ULONG_PTR}
  ULONG_PTR   = NativeUInt;
  {$EXTERNALSYM size_t}
  size_t      = NativeUInt;
{$ENDIF}
  {$EXTERNALSYM LPINT}
  LPINT       = ^Integer;
  {$EXTERNALSYM LPFILETIME}
  LPFILETIME  = PFileTime;
  {$EXTERNALSYM LONG}
  LONG        = Longint;
  {$EXTERNALSYM HANDLE}
  HANDLE      = THANDLE;

implementation

end.
