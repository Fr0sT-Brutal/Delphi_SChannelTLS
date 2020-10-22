{
  Helper functions for easy implementation of TLS communication by means of
  Windows SChannel.
  The functions are transport-agnostic so they could be applied to any socket
  implementation or even other transport.

  Inspired by [TLS-Sample](http://www.coastrd.com/c-schannel-smtp)

  Uses [JEDI API units](https://jedi-apilib.sourceforge.net)

  (c) Fr0sT-Brutal
  
  License MIT
}

unit SChannel.Utils;

interface
{$IFDEF MSWINDOWS}

uses
  Windows, SysUtils,
  JwaBaseTypes, JwaWinError, JwaWinCrypt, JwaSspi, JwaSChannel;

const
  LogPrefix = '[SChannel]: '; // Just a suggested prefix for log output
  IO_BUFFER_SIZE = $10000;    // Size of handshake buffer
  // Set of used protocols.
  // Note: TLS 1.0 is not used by default, add `SP_PROT_TLS1_0` if needed
  USED_PROTOCOLS: DWORD = SP_PROT_TLS1_1 or SP_PROT_TLS1_2;
  // Set of used algorithms.
  // `0` means default. Add `CALG_DH_EPHEM`, `CALG_RSA_KEYX`, etc if needed
  USED_ALGS: ALG_ID = 0;

type
  // Stage of handshake
  THandShakeStage = (
    // Initial stage
    hssNotStarted,
    // Sending client hello
    hssSendCliHello,
    // Reading server hello - general
    hssReadSrvHello,
    // Reading server hello - repeat call without reading
    hssReadSrvHelloNoRead,
    // Reading server hello - in process, send token
    hssReadSrvHelloContNeed,
    // Reading server hello - success, send token
    hssReadSrvHelloOK,
    // Final stage
    hssDone
  );

  // State of secure channel
  TChannelState = (
    // Initial stage
    chsNotStarted,
    // Handshaking with server
    chsHandshake,
    // Channel established successfully
    chsEstablished,
    // Sending shutdown signal and closing connection
    chsShutdown
  );

  // United state and data for TLS handshake
  THandShakeData = record
    // Current stage
    Stage: THandShakeStage;
    // Name of domain we're connecting to.
    // IN at hssNotStarted
    ServerName: string;
    // Handle of security context.
    // OUT after hssSendCliHello, IN at hssReadSrvHello*
    hContext: CtxtHandle;
    // Buffer with data from server.
    // IN at hssReadSrvHello*
    IoBuffer: TBytes;
    // Size of data in buffer.
    cbIoBuffer: DWORD;
    // Array of SChannel-allocated buffers that must be disposed with `g_pSSPI.FreeContextBuffer`.
    // OUT after hssSendCliHello, hssReadSrvHelloContNeed, hssReadSrvHelloOK
    OutBuffers: array of SecBuffer;
  end;

  // Session options
  TSessionFlag = (
    // If @true, SChannel won't verify server certificate (use with care! Though
    // this could help when connecting by IP)
    sfNoServerVerify
  );
  TSessionFlags = set of TSessionFlag;

  // Data related to a session. Using a variable of this type allows thread-safe
  // usage
  TSessionData = record
    // Options
    Flags: TSessionFlags;
    // Handle of credentials, mainly for internal use
    hCreds: CredHandle;
    // SChannel credentials, mainly for internal use but could be init-ed by user
    // to tune specific channel properties.
    SchannelCred: SCHANNEL_CRED;
  end;
  PSessionData = ^TSessionData;

  // Trivial data storage
  TBuffer = record
    Data: TBytes;          // Buffer for data
    DataStartIdx: Integer; // Index in buffer the unprocessed data starts from
    DataLen: Cardinal;     // Length of unprocessed data
  end;

  // Interface with session data for sharing credentials
  ISharedSessionData = interface
    // Return pointer to `TSessionData` record
    function GetSessionDataPtr: PSessionData;
  end;

  // Interfaced object with session data for sharing credentials
  TSharedSessionData = class(TInterfacedObject, ISharedSessionData)
  strict private
    FSessionData: TSessionData;
  public
    constructor Create(const SessionData: TSessionData);
    destructor Destroy; override;
    function GetSessionDataPtr: PSessionData;
  end;

  // Specific exception class. Could be created on WinAPI error, SChannel error
  // or general internal error.
  ESSPIError = class(Exception)
  public
    // If not zero, reason of exception is WinAPI and this field contains code of
    // an error returned by GetLastError
    WinAPIErr: DWORD;
    // If not zero, reason of exception is SChannel and this field contains
    // security status returned by last function call
    SecStatus: SECURITY_STATUS;

    // Create WinAPI exception based on Err code
    constructor CreateWinAPI(const Action, Func: string; Err: DWORD);
    // Create SChannel exception based on status
    constructor CreateSecStatus(const Action, Func: string; Status: SECURITY_STATUS);
  end;

var
  // ~~ Globals that are set/cleared by Init & Fin functions ~~
  hMYCertStore: HCERTSTORE = nil;
  g_pSSPI: PSecurityFunctionTable;

// ~~ Init utils - usually not to be called by user ~~

// Mainly for internal use
// @raises ESSPIError on error
procedure LoadSecurityLibrary;
// Mainly for internal use
//   @param SchannelCred - [?IN/OUT] If `SchannelCred.dwVersion` = `SCHANNEL_CRED_VERSION`,              \
//     the parameter is considered "IN/OUT" and won't be modified before `AcquireCredentialsHandle` call.\
//     Otherwise the parameter is considered "OUT" and is init-ed with default values.                   \
//     Thus user can pass desired values to `AcquireCredentialsHandle` function.
// @raises ESSPIError on error
procedure CreateCredentials(const User: string; out hCreds: CredHandle; var SchannelCred: SCHANNEL_CRED);
// Mainly for internal use. Gets called by `CheckServerCert`
// @raises ESSPIError on error
procedure VerifyServerCertificate(pServerCert: PCCERT_CONTEXT; const szServerName: string; dwCertFlags: DWORD);

// ~~ Global init and fin ~~
// Load global stuff. Must be called before any other function called.
// Could be called multiple times without checks. @br
// **Thread-unsafe! Uses global variables**
// @raises ESSPIError on error
procedure Init;
// Dispose and nullify global stuff.
// Could be called multiple times without checks. @br
// **Thread-unsafe! Uses global variables**
procedure Fin;

// ~~ Session init and fin ~~

// Init session, return data record to be used in calling other functions.
// Could be called multiple times (nothing will be done on already init-ed record)
//   @param SessionData - [IN, OUT] record that receives values. On first call   \
//     must be zeroed. Alternatively, user could fill `SessionData.SchannelCred` \
//     with desired values to tune channel properties.
// @raises ESSPIError on error
procedure InitSession(var SessionData: TSessionData);
// Finalize session
procedure FinSession(var SessionData: TSessionData);

// ~~ Start/close connection ~~

// Function to prepare all necessary handshake data. No transport level actions.
// @raises ESSPIError on error
function DoClientHandshake(var SessionData: TSessionData; var HandShakeData: THandShakeData): SECURITY_STATUS;
// Generate data to send to a server on connection shutdown
// @raises ESSPIError on error
procedure GetShutdownData(const SessionData: TSessionData; const hContext: CtxtHandle;
  out OutBuffer: SecBuffer);
// Check server certificate
// @raises ESSPIError on error
procedure CheckServerCert(const hContext: CtxtHandle; const ServerName: string);
// Dispose and nullify security context
procedure DeleteContext(var hContext: CtxtHandle);

// ~~ Data exchange ~~

// Receive size values for current session and init buffer length to contain
// full message including header and trailer
// @raises ESSPIError on error
procedure InitBuffers(const hContext: CtxtHandle; out pbIoBuffer: TBytes;
  out Sizes: SecPkgContext_StreamSizes);
// Encrypt data (prepare for sending to server).
//   @param hContext - current session context
//   @param Sizes - current session sizes
//   @param pbMessage - input data to encrypt
//   @param cbMessage - length of input data
//   @param pbIoBuffer - buffer to receive encrypted data
//   @param pbIoBufferLength - size of buffer
//   @param cbWritten - [OUT] size of encrypted data written to buffer
// @raises ESSPIError on error
procedure EncryptData(const hContext: CtxtHandle; const Sizes: SecPkgContext_StreamSizes;
  pbMessage: PByte; cbMessage: DWORD; pbIoBuffer: PByte; pbIoBufferLength: DWORD;
  out cbWritten: DWORD);
// Decrypt data received from server. If input data is not processed completely,
// unprocessed chunk is copied to beginning of buffer. Thus subsequent call to
// Recv could just receive to @Buffer[DataLength]
//   @param hContext - current session context
//   @param Sizes - current session sizes
//   @param pbIoBuffer - input encrypted data to decrypt
//   @param cbEncData - [IN/OUT] length of encrypted data in buffer.    \
//     After function call it is set to amount of unprocessed data that \
//     is placed from the beginning of the buffer
//   @param pbDecData - buffer to receive decrypted data
//   @param cbDecDataLength - size of buffer
//   @param cbWritten - [OUT] size of decrypted data written to buffer
// @returns                                                                    \
//   * `SEC_I_CONTEXT_EXPIRED` - server signaled end of session                \
//   * `SEC_E_OK` - message processed fully                                    \
//   * `SEC_E_INCOMPLETE_MESSAGE` - need more data                             \
//   * `SEC_I_RENEGOTIATE` - server wants to perform another handshake sequence
// @raises ESSPIError on error or if Result is not one of above mentioned values
function DecryptData(const hContext: CtxtHandle; const Sizes: SecPkgContext_StreamSizes;
  pbIoBuffer: PByte; var cbEncData: DWORD;
  pbDecData: PByte; cbDecDataLength: DWORD; out cbWritten: DWORD): SECURITY_STATUS;

// ~~ Misc ~~

// Check if handle `x` is null (has both fields equal to zero)
function SecIsNullHandle(const x: SecHandle): Boolean;
// Returns string representaion of given security status
function SecStatusErrStr(scRet: SECURITY_STATUS): string;
// Returns string representaion of given verify trust error
function WinVerifyTrustErrorStr(Status: DWORD): string;
// Check if status is likely a Windows TLS v1.2 handshake bug (`SEC_E_BUFFER_TOO_SMALL`
//  or `SEC_E_MESSAGE_ALTERED` status is returned by `InitializeSecurityContext` on handshake).
// This function only checks if parameter is one of these two values.
function IsWinHandshakeBug(scRet: SECURITY_STATUS): Boolean;

// Messages that could be written to log by various implementations. None of these
// are used in this unit
const
  S_Msg_Received = 'Received %d bytes of encrypted data / %d bytes of payload';
  S_Msg_SessionClosed = 'Server closed the session [SEC_I_CONTEXT_EXPIRED]';
  S_Msg_Renegotiate = 'Server requested renegotiate';
  S_Msg_Sending = 'Sending %d bytes of payload / %d bytes encrypted';
  S_Msg_StartingTLS = 'Starting TLS handshake';
  S_Msg_HShStageW1Success = 'Handshake @W1 - %d bytes sent';
  S_Msg_HShStageW1Fail = 'Handshake @W1 - ! error sending data';
  S_Msg_HShStageRFail = 'Handshake @R - no data received or error receiving';
  S_Msg_HShStageRSuccess = 'Handshake @R - %d bytes received';
  S_Msg_HandshakeBug = 'Handshake bug: "%s", retrying';
  S_Msg_HShStageW2Success = 'Handshake @W2 - %d bytes sent';
  S_Msg_HShStageW2Fail = 'Handshake @W2 - ! error sending data';
  S_Msg_HShExtraData = 'Handshake: got "%d" bytes of extra data';
  S_Msg_Established = 'Handshake established';
  S_Msg_SrvCredsAuth = 'Server credentials authenticated';
  S_Msg_CredsInited = 'Credentials initialized';
  S_Msg_ShuttingDownTLS = 'Shutting down TLS';
  S_Msg_SendingShutdown = 'Sending shutdown notify - %d bytes of data';
  S_Err_ListeningNotSupported = 'Listening is not supported with SChannel yet';

{$ENDIF MSWINDOWS}

implementation
{$IFDEF MSWINDOWS}

const
  // %0s - current action, like 'sending data' or 'at Init'
  // %1s - WinAPI method, like 'Send'
  // %2d - error code
  // %3s - error message for error code
  S_E_WinAPIErrPatt = 'Error %s calling WinAPI method "%s": [%d] %s';
  // %0s - current action, like 'at CreateCredentials'
  // %1s - SChannel method, like 'AcquireCredentialsHandle'
  // %2s - error message
  S_E_SecStatusErrPatt = 'Error %s calling method "%s": %s';

// ~~ Utils ~~

function SecIsNullHandle(const x: SecHandle): Boolean;
begin
  Result := (x.dwLower = 0) and (x.dwUpper = 0);
end;

function SecStatusErrStr(scRet: SECURITY_STATUS): string;
begin
  case scRet of
    SEC_E_INSUFFICIENT_MEMORY           : Result := 'SEC_E_INSUFFICIENT_MEMORY';
    SEC_E_INVALID_HANDLE                : Result := 'SEC_E_INVALID_HANDLE';
    SEC_E_UNSUPPORTED_FUNCTION          : Result := 'SEC_E_UNSUPPORTED_FUNCTION';
    SEC_E_TARGET_UNKNOWN                : Result := 'SEC_E_TARGET_UNKNOWN';
    SEC_E_INTERNAL_ERROR                : Result := 'SEC_E_INTERNAL_ERROR';
    SEC_E_SECPKG_NOT_FOUND              : Result := 'SEC_E_SECPKG_NOT_FOUND';
    SEC_E_NOT_OWNER                     : Result := 'SEC_E_NOT_OWNER';
    SEC_E_CANNOT_INSTALL                : Result := 'SEC_E_CANNOT_INSTALL';
    SEC_E_INVALID_TOKEN                 : Result := 'SEC_E_INVALID_TOKEN';
    SEC_E_CANNOT_PACK                   : Result := 'SEC_E_CANNOT_PACK';
    SEC_E_QOP_NOT_SUPPORTED             : Result := 'SEC_E_QOP_NOT_SUPPORTED';
    SEC_E_NO_IMPERSONATION              : Result := 'SEC_E_NO_IMPERSONATION';
    SEC_E_LOGON_DENIED                  : Result := 'SEC_E_LOGON_DENIED';
    SEC_E_UNKNOWN_CREDENTIALS           : Result := 'SEC_E_UNKNOWN_CREDENTIALS';
    SEC_E_NO_CREDENTIALS                : Result := 'SEC_E_NO_CREDENTIALS';
    SEC_E_MESSAGE_ALTERED               : Result := 'SEC_E_MESSAGE_ALTERED';
    SEC_E_OUT_OF_SEQUENCE               : Result := 'SEC_E_OUT_OF_SEQUENCE';
    SEC_E_NO_AUTHENTICATING_AUTHORITY   : Result := 'SEC_E_NO_AUTHENTICATING_AUTHORITY';
    SEC_I_CONTINUE_NEEDED               : Result := 'SEC_I_CONTINUE_NEEDED';
    SEC_I_COMPLETE_NEEDED               : Result := 'SEC_I_COMPLETE_NEEDED';
    SEC_I_COMPLETE_AND_CONTINUE         : Result := 'SEC_I_COMPLETE_AND_CONTINUE';
    SEC_I_LOCAL_LOGON                   : Result := 'SEC_I_LOCAL_LOGON';
    SEC_E_BAD_PKGID                     : Result := 'SEC_E_BAD_PKGID';
    SEC_E_CONTEXT_EXPIRED               : Result := 'SEC_E_CONTEXT_EXPIRED';
    SEC_I_CONTEXT_EXPIRED               : Result := 'SEC_I_CONTEXT_EXPIRED';
    SEC_E_INCOMPLETE_MESSAGE            : Result := 'SEC_E_INCOMPLETE_MESSAGE';
    SEC_E_INCOMPLETE_CREDENTIALS        : Result := 'SEC_E_INCOMPLETE_CREDENTIALS';
    SEC_E_BUFFER_TOO_SMALL              : Result := 'SEC_E_BUFFER_TOO_SMALL';
    SEC_I_INCOMPLETE_CREDENTIALS        : Result := 'SEC_I_INCOMPLETE_CREDENTIALS';
    SEC_I_RENEGOTIATE                   : Result := 'SEC_I_RENEGOTIATE';
    SEC_E_WRONG_PRINCIPAL               : Result := 'SEC_E_WRONG_PRINCIPAL';
    SEC_I_NO_LSA_CONTEXT                : Result := 'SEC_I_NO_LSA_CONTEXT';
    SEC_E_TIME_SKEW                     : Result := 'SEC_E_TIME_SKEW';
    SEC_E_UNTRUSTED_ROOT                : Result := 'SEC_E_UNTRUSTED_ROOT';
    SEC_E_ILLEGAL_MESSAGE               : Result := 'SEC_E_ILLEGAL_MESSAGE';
    SEC_E_CERT_UNKNOWN                  : Result := 'SEC_E_CERT_UNKNOWN';
    SEC_E_CERT_EXPIRED                  : Result := 'SEC_E_CERT_EXPIRED';
    SEC_E_ENCRYPT_FAILURE               : Result := 'SEC_E_ENCRYPT_FAILURE';
    SEC_E_DECRYPT_FAILURE               : Result := 'SEC_E_DECRYPT_FAILURE';
    SEC_E_ALGORITHM_MISMATCH            : Result := 'SEC_E_ALGORITHM_MISMATCH';
    SEC_E_SECURITY_QOS_FAILED           : Result := 'SEC_E_SECURITY_QOS_FAILED';
    SEC_E_UNFINISHED_CONTEXT_DELETED    : Result := 'SEC_E_UNFINISHED_CONTEXT_DELETED';
    SEC_E_NO_TGT_REPLY                  : Result := 'SEC_E_NO_TGT_REPLY';
    SEC_E_NO_IP_ADDRESSES               : Result := 'SEC_E_NO_IP_ADDRESSES';
    SEC_E_WRONG_CREDENTIAL_HANDLE       : Result := 'SEC_E_WRONG_CREDENTIAL_HANDLE';
    SEC_E_CRYPTO_SYSTEM_INVALID         : Result := 'SEC_E_CRYPTO_SYSTEM_INVALID';
    SEC_E_MAX_REFERRALS_EXCEEDED        : Result := 'SEC_E_MAX_REFERRALS_EXCEEDED';
    SEC_E_MUST_BE_KDC                   : Result := 'SEC_E_MUST_BE_KDC';
    SEC_E_STRONG_CRYPTO_NOT_SUPPORTED   : Result := 'SEC_E_STRONG_CRYPTO_NOT_SUPPORTED';
    SEC_E_TOO_MANY_PRINCIPALS           : Result := 'SEC_E_TOO_MANY_PRINCIPALS';
    SEC_E_NO_PA_DATA                    : Result := 'SEC_E_NO_PA_DATA';
    SEC_E_PKINIT_NAME_MISMATCH          : Result := 'SEC_E_PKINIT_NAME_MISMATCH';
    SEC_E_SMARTCARD_LOGON_REQUIRED      : Result := 'SEC_E_SMARTCARD_LOGON_REQUIRED';
    SEC_E_SHUTDOWN_IN_PROGRESS          : Result := 'SEC_E_SHUTDOWN_IN_PROGRESS';
    SEC_E_KDC_INVALID_REQUEST           : Result := 'SEC_E_KDC_INVALID_REQUEST';
    SEC_E_KDC_UNABLE_TO_REFER           : Result := 'SEC_E_KDC_UNABLE_TO_REFER';
    SEC_E_KDC_UNKNOWN_ETYPE             : Result := 'SEC_E_KDC_UNKNOWN_ETYPE';
    SEC_E_UNSUPPORTED_PREAUTH           : Result := 'SEC_E_UNSUPPORTED_PREAUTH';
    SEC_E_DELEGATION_REQUIRED           : Result := 'SEC_E_DELEGATION_REQUIRED';
    SEC_E_BAD_BINDINGS                  : Result := 'SEC_E_BAD_BINDINGS';
    SEC_E_MULTIPLE_ACCOUNTS             : Result := 'SEC_E_MULTIPLE_ACCOUNTS';
    SEC_E_NO_KERB_KEY                   : Result := 'SEC_E_NO_KERB_KEY';
    SEC_E_CERT_WRONG_USAGE              : Result := 'SEC_E_CERT_WRONG_USAGE';
    SEC_E_DOWNGRADE_DETECTED            : Result := 'SEC_E_DOWNGRADE_DETECTED';
    SEC_E_SMARTCARD_CERT_REVOKED        : Result := 'SEC_E_SMARTCARD_CERT_REVOKED';
    SEC_E_ISSUING_CA_UNTRUSTED          : Result := 'SEC_E_ISSUING_CA_UNTRUSTED';
    SEC_E_REVOCATION_OFFLINE_C          : Result := 'SEC_E_REVOCATION_OFFLINE_C';
    SEC_E_PKINIT_CLIENT_FAILURE         : Result := 'SEC_E_PKINIT_CLIENT_FAILURE';
    SEC_E_SMARTCARD_CERT_EXPIRED        : Result := 'SEC_E_SMARTCARD_CERT_EXPIRED';
    SEC_E_NO_S4U_PROT_SUPPORT           : Result := 'SEC_E_NO_S4U_PROT_SUPPORT';
    SEC_E_CROSSREALM_DELEGATION_FAILURE : Result := 'SEC_E_CROSSREALM_DELEGATION_FAILURE';
    SEC_E_REVOCATION_OFFLINE_KDC        : Result := 'SEC_E_REVOCATION_OFFLINE_KDC';
    SEC_E_ISSUING_CA_UNTRUSTED_KDC      : Result := 'SEC_E_ISSUING_CA_UNTRUSTED_KDC';
    SEC_E_KDC_CERT_EXPIRED              : Result := 'SEC_E_KDC_CERT_EXPIRED';
    SEC_E_KDC_CERT_REVOKED              : Result := 'SEC_E_KDC_CERT_REVOKED';
    else Result := 'Unknown ' + IntToStr(scRet);
  end;
end;

function WinVerifyTrustErrorStr(Status: DWORD): string;
begin
  case HRESULT(Status) of
    CERT_E_EXPIRED               : Result := 'CERT_E_EXPIRED';
    CERT_E_VALIDITYPERIODNESTING : Result := 'CERT_E_VALIDITYPERIODNESTING';
    CERT_E_ROLE                  : Result := 'CERT_E_ROLE';
    CERT_E_PATHLENCONST          : Result := 'CERT_E_PATHLENCONST';
    CERT_E_CRITICAL              : Result := 'CERT_E_CRITICAL';
    CERT_E_PURPOSE               : Result := 'CERT_E_PURPOSE';
    CERT_E_ISSUERCHAINING        : Result := 'CERT_E_ISSUERCHAINING';
    CERT_E_MALFORMED             : Result := 'CERT_E_MALFORMED';
    CERT_E_UNTRUSTEDROOT         : Result := 'CERT_E_UNTRUSTEDROOT';
    CERT_E_CHAINING              : Result := 'CERT_E_CHAINING';
    TRUST_E_FAIL                 : Result := 'TRUST_E_FAIL';
    CERT_E_REVOKED               : Result := 'CERT_E_REVOKED';
    CERT_E_UNTRUSTEDTESTROOT     : Result := 'CERT_E_UNTRUSTEDTESTROOT';
    CERT_E_REVOCATION_FAILURE    : Result := 'CERT_E_REVOCATION_FAILURE';
    CERT_E_CN_NO_MATCH           : Result := 'CERT_E_CN_NO_MATCH';
    CERT_E_WRONG_USAGE           : Result := 'CERT_E_WRONG_USAGE';
    else Result := 'Unknown ' + IntToStr(Status);
  end;
end;

function IsWinHandshakeBug(scRet: SECURITY_STATUS): Boolean;
begin
  Result := (scRet = SEC_E_BUFFER_TOO_SMALL) or (scRet = SEC_E_MESSAGE_ALTERED);
end;

{ ~~ TSharedSessionData ~~ }

constructor TSharedSessionData.Create(const SessionData: TSessionData);
begin
  inherited Create;
  FSessionData := SessionData;
end;

// Return pointer to `TSessionData` record
function TSharedSessionData.GetSessionDataPtr: PSessionData;
begin
  Result := @FSessionData;
end;

destructor TSharedSessionData.Destroy;
begin
  FinSession(FSessionData);
  inherited;
end;

{ ~~ ESSPIError ~~ }

{
  Create WinAPI exception based on Err code
    @param Action - current action, like `sending data` or `at Init`
    @param Func - WinAPI method, like `Send`
    @param Err - error code
}
constructor ESSPIError.CreateWinAPI(const Action, Func: string; Err: DWORD);
begin
  inherited CreateFmt(S_E_WinAPIErrPatt, [Action, Func, Err, SysErrorMessage(Err)]);
  Self.WinAPIErr := Err;
end;

{
  Create SChannel exception based on status
    @param Action - current action, like `at CreateCredentials`
    @param Func - SChannel method, like `AcquireCredentialsHandle`
    @param Status - SChannel status
}
constructor ESSPIError.CreateSecStatus(const Action, Func: string;
  Status: SECURITY_STATUS);
begin
  inherited CreateFmt(S_E_SecStatusErrPatt, [Action, Func, SecStatusErrStr(Status)]);
  Self.SecStatus := Status;
end;

// Create general exception
function Error(const Msg: string; const Args: array of const): ESSPIError; overload;
begin
  Result := ESSPIError.CreateFmt(Msg, Args);
end;

function Error(const Msg: string): ESSPIError; overload;
begin
  Result := ESSPIError.Create(Msg);
end;

// Create security status exception
function ErrSecStatus(const Action, Func: string; Status: SECURITY_STATUS): ESSPIError;
begin
  Result := ESSPIError.CreateSecStatus(Action, Func, Status);
end;

// Create WinAPI exception based on GetLastError
function ErrWinAPI(const Action, Func: string): ESSPIError;
begin
  Result := ESSPIError.CreateWinAPI(Action, Func, GetLastError);
end;

procedure Debug(const Msg: string);
begin
  OutputDebugString(PChar(Msg));
end;

// ~~ Init & fin ~~

procedure LoadSecurityLibrary;
begin
  g_pSSPI := InitSecurityInterface;
  if g_pSSPI = nil then
    raise ErrWinAPI('@ LoadSecurityLibrary', 'InitSecurityInterface');
end;

procedure CreateCredentials(const User: string; out hCreds: CredHandle; var SchannelCred: SCHANNEL_CRED);
var
  tsExpiry: TimeStamp;
  cSupportedAlgs: DWORD;
  rgbSupportedAlgs: array[0..15] of ALG_ID;
  pCertContext: PCCERT_CONTEXT;
  Status: SECURITY_STATUS;
begin
  // If a user name is specified, then attempt to find a client
  // certificate. Otherwise, just create a NULL credential.
  if User <> '' then
  begin
    // Find client certificate. Note that this sample just searches for a
    // certificate that contains the user name somewhere in the subject name.
    // A real application should be a bit less casual.
    pCertContext := CertFindCertificateInStore(hMyCertStore,                     // hCertStore
                                               X509_ASN_ENCODING,             // dwCertEncodingType
                                               0,                                             // dwFindFlags
                                               CERT_FIND_SUBJECT_STR_A,// dwFindType
                                               Pointer(User),                         // *pvFindPara
                                               nil);                                 // pPrevCertContext

    if pCertContext = nil then
      raise ErrWinAPI('@ CreateCredentials', 'CertFindCertificateInStore');
  end
  else
    pCertContext := nil;

  // Schannel credential structure not inited yet - fill with default values.
  // Otherwise let the user pass his own values.
  if SchannelCred.dwVersion <> SCHANNEL_CRED_VERSION then
  begin
    // Build Schannel credential structure. Currently, this sample only
    // specifies the protocol to be used (and optionally the certificate,
    // of course). Real applications may wish to specify other parameters as well.
    SchannelCred := Default(SCHANNEL_CRED);

    SchannelCred.dwVersion := SCHANNEL_CRED_VERSION;
    if pCertContext <> nil then
    begin
      SchannelCred.cCreds := 1;
      SchannelCred.paCred := @pCertContext;
    end;
    SchannelCred.grbitEnabledProtocols := USED_PROTOCOLS;

    cSupportedAlgs := 0;

    if USED_ALGS <> 0 then
    begin
      rgbSupportedAlgs[cSupportedAlgs] := USED_ALGS;
      Inc(cSupportedAlgs);
    end;

    if cSupportedAlgs <> 0 then
    begin
      SchannelCred.cSupportedAlgs    := cSupportedAlgs;
      SchannelCred.palgSupportedAlgs := @rgbSupportedAlgs;
    end;

    SchannelCred.dwFlags := SCH_CRED_REVOCATION_CHECK_CHAIN;
  end;

  // Create an SSPI credential with SChannel security package
  Status := g_pSSPI.AcquireCredentialsHandleW(nil,         // Name of principal
                                              PSecWChar(PChar(UNISP_NAME)),     // Name of package
                                              SECPKG_CRED_OUTBOUND, // Flags indicating use
                                              nil,         // Pointer to logon ID
                                              @SchannelCred,        // Package specific data
                                              nil,         // Pointer to GetKey() func
                                              nil,         // Value to pass to GetKey()
                                              @hCreds,        // (out) Cred Handle
                                              @tsExpiry);      // (out) Lifetime (optional)

  // cleanup: Free the certificate context. Schannel has already made its own copy.
  if pCertContext <> nil then
    CertFreeCertificateContext(pCertContext);

  if Status <> SEC_E_OK then
    raise ErrSecStatus('@ CreateCredentials', 'AcquireCredentialsHandle', Status);
end;

procedure Init;
begin
  if g_pSSPI = nil then
    LoadSecurityLibrary;
  // Open the "MY" certificate store, where IE stores client certificates.
  // Windows maintains 4 stores -- MY, CA, ROOT, SPC.
  if hMYCertStore = nil then
  begin
    hMYCertStore := CertOpenSystemStore(0, 'MY');
    if hMYCertStore = nil then
      raise ErrWinAPI('@ Init', 'CertOpenSystemStore');
  end;
end;

procedure Fin;
begin
  // Close "MY" certificate store.
  if hMYCertStore <> nil then
    CertCloseStore(hMYCertStore, 0);
  hMYCertStore := nil;
  g_pSSPI := nil;
end;

procedure InitSession(var SessionData: TSessionData);
begin
  if SecIsNullHandle(SessionData.hCreds) then
  begin
    // Create credentials
    CreateCredentials('', SessionData.hCreds, SessionData.SchannelCred);
  end;
end;

procedure FinSession(var SessionData: TSessionData);
begin
  if not SecIsNullHandle(SessionData.hCreds) then
  begin
    // Free SSPI credentials handle.
    g_pSSPI.FreeCredentialsHandle(@SessionData.hCreds);
    SessionData.hCreds := Default(CredHandle);
    SessionData.SchannelCred := Default(SCHANNEL_CRED);
  end;
end;

// ~~ Connect & close ~~

// Try to get new client credentials, leaving old value on error
procedure GetNewClientCredentials(var SessionData: TSessionData; const hContext: CtxtHandle);
var
  IssuerListInfo: SecPkgContext_IssuerListInfoEx;
  pChainContext: PCCERT_CHAIN_CONTEXT;
  FindByIssuerPara: CERT_CHAIN_FIND_BY_ISSUER_PARA;
  pCertContext: PCCERT_CONTEXT;
  tsExpiry: TimeStamp;
  Status: SECURITY_STATUS;
  hCreds: CredHandle;
begin
  // Read list of trusted issuers from schannel.
  Status := g_pSSPI.QueryContextAttributesW(@hContext, SECPKG_ATTR_ISSUER_LIST_EX, @IssuerListInfo);
  if Status <> SEC_E_OK then
    raise ErrSecStatus('@ GetNewClientCredentials', 'QueryContextAttributesW', Status);

  // Enumerate the client certificates.
  FindByIssuerPara := Default(CERT_CHAIN_FIND_BY_ISSUER_PARA);
  FindByIssuerPara.cbSize := SizeOf(FindByIssuerPara);
  FindByIssuerPara.pszUsageIdentifier := szOID_PKIX_KP_CLIENT_AUTH;
  FindByIssuerPara.dwKeySpec := 0;
  FindByIssuerPara.cIssuer   := IssuerListInfo.cIssuers;
  FindByIssuerPara.rgIssuer  := IssuerListInfo.aIssuers;

  pChainContext := nil;

  while True do
  begin
    // Find a certificate chain.
    pChainContext := CertFindChainInStore(hMYCertStore,
                                          X509_ASN_ENCODING,
                                          0,
                                          CERT_CHAIN_FIND_BY_ISSUER,
                                          @FindByIssuerPara,
                                          pChainContext);
    if pChainContext = nil then
    begin
      Debug('GetNewClientCredentials: error in CertFindChainInStore finding cert chain - ' + SysErrorMessage(GetLastError));
      Break;
    end;

    // Get pointer to leaf certificate context.
    pCertContext := pChainContext.rgpChain^.rgpElement^.pCertContext;

    // Create schannel credential.
    SessionData.SchannelCred.dwVersion := SCHANNEL_CRED_VERSION;
    SessionData.SchannelCred.cCreds := 1;
    SessionData.SchannelCred.paCred := @pCertContext;

    Status := g_pSSPI.AcquireCredentialsHandleW(nil,                          // Name of principal
                                                PSecWChar(PChar(UNISP_NAME)), // Name of package
                                                SECPKG_CRED_OUTBOUND,         // Flags indicating use
                                                nil,                          // Pointer to logon ID
                                                @SessionData.SchannelCred,    // Package specific data
                                                nil,                          // Pointer to GetKey() func
                                                nil,                          // Value to pass to GetKey()
                                                @hCreds,                      // (out) Cred Handle
                                                @tsExpiry);                   // (out) Lifetime (optional)

    if Status <> SEC_E_OK then
      Continue;

    g_pSSPI.FreeCredentialsHandle(@SessionData.hCreds); // Destroy the old credentials.
    SessionData.hCreds := hCreds;
  end; // while
end;

{
 Function to prepare all necessary handshake data. No transport level actions.
   @param SessionData - [IN/OUT] record with session data
   @param HandShakeData - [IN/OUT] record with handshake data
   @raises ESSPIError on error
 Function actions and returning data depending on input stage:
  - `HandShakeData.Stage` = hssNotStarted. Generate client hello. @br
     *Output stage*: hssSendCliHello. @br
     *Caller action*: send returned data (client hello) to server @br
     *Input data*:
       - ServerName - host we're connecting to

     *Output data*:
       - hContext - handle to secure context
       - OutBuffers - array with single item that must be finally disposed
         with `g_pSSPI.FreeContextBuffer`

  - `HandShakeData.Stage` = hssSendCliHello. **Not** handled by @name @br

  - `HandShakeData.Stage` = hssReadSrvHello, hssReadSrvHelloNoRead,
       hssReadSrvHelloContNeed. Handle server hello

     *Output stage*: hssReadSrvHello, hssReadSrvHelloNoRead,
       hssReadSrvHelloContNeed, hssReadSrvHelloOK. @br
     *Caller action*:
       - hssReadSrvHello: read data from server and call @name again
       - hssReadSrvHelloNoRead: call @name again without reading
       - hssReadSrvHelloContNeed: send token returned in `OutBuffers` and call @name again
       - hssReadSrvHelloOK: send token returned in `OutBuffers` and finish

     *Input data*:
       - ServerName - host we're connecting to
       - IoBuffer - buffer with data from server
       - cbIoBuffer - size of data in buffer

     *Output data*:
       - IoBuffer - buffer with unprocessed data from server
       - cbIoBuffer - length of unprocessed data from server
       - OutBuffers - array with single item that must be finally disposed
         with `g_pSSPI.FreeContextBuffer` (hssReadSrvHelloContNeed, hssReadSrvHelloOK)

  - `HandShakeData.Stage` = hssReadSrvHelloOK. **Not** handled by @name @br

  - `HandShakeData.Stage` = hssDone. **Not** handled by @name @br
}
function DoClientHandshake(var SessionData: TSessionData; var HandShakeData: THandShakeData): SECURITY_STATUS;

  // Process "extra" buffer and modify HandShakeData.cbIoBuffer accordingly.
  // After the call HandShakeData.IoBuffer will contain HandShakeData.cbIoBuffer
  // (including zero!) unprocessed data.
  procedure HandleBuffers(const InBuffer: SecBuffer);
  begin
    if InBuffer.BufferType = SECBUFFER_EXTRA then
    begin
      Move(
        (PByte(HandShakeData.IoBuffer) + (HandShakeData.cbIoBuffer - InBuffer.cbBuffer))^,
        Pointer(HandShakeData.IoBuffer)^,
        InBuffer.cbBuffer);
      HandShakeData.cbIoBuffer := InBuffer.cbBuffer;
    end
    else
      HandShakeData.cbIoBuffer := 0; // Prepare for the next recv
  end;

var
  dwSSPIFlags, dwSSPIOutFlags: DWORD;
  tsExpiry: TimeStamp;
  InBuffers: array [0..1] of SecBuffer;
  OutBuffer, InBuffer: SecBufferDesc;
begin
  dwSSPIFlags :=
    ISC_REQ_SEQUENCE_DETECT or ISC_REQ_REPLAY_DETECT or ISC_REQ_CONFIDENTIALITY or
    ISC_RET_EXTENDED_ERROR or ISC_REQ_ALLOCATE_MEMORY or ISC_REQ_STREAM;
  if sfNoServerVerify in SessionData.Flags then
    dwSSPIFlags := dwSSPIFlags or ISC_REQ_MANUAL_CRED_VALIDATION;

  case HandShakeData.Stage of
    hssNotStarted:
      begin
        //  Initiate a ClientHello message and generate a token.
        SetLength(HandShakeData.OutBuffers, 1);
        HandShakeData.OutBuffers[0] := Default(SecBuffer);
        HandShakeData.OutBuffers[0].BufferType := SECBUFFER_TOKEN;

        OutBuffer.ulVersion := SECBUFFER_VERSION;
        OutBuffer.cBuffers  := Length(HandShakeData.OutBuffers);
        OutBuffer.pBuffers  := PSecBuffer(HandShakeData.OutBuffers);

        Result := g_pSSPI.InitializeSecurityContextW(@SessionData.hCreds,
                                                     nil,  // NULL on the first call
                                                     PSecWChar(Pointer(HandShakeData.ServerName)), // ! PChar('') <> nil !
                                                     dwSSPIFlags,
                                                     0,    // Reserved
                                                     0,    // Not used with Schannel
                                                     nil,  // NULL on the first call
                                                     0,    // Reserved
                                                     @HandShakeData.hContext,
                                                     @OutBuffer,
                                                     dwSSPIOutFlags,
                                                     @tsExpiry);

        if Result <> SEC_I_CONTINUE_NEEDED then
          raise ErrSecStatus('@ DoClientHandshake @ client hello', 'InitializeSecurityContext', Result);
        if (HandShakeData.OutBuffers[0].cbBuffer = 0) or (HandShakeData.OutBuffers[0].pvBuffer = nil) then
          raise Error('Error @ DoClientHandshake @ client hello: InitializeSecurityContext generated empty buffer');

        HandShakeData.Stage := hssSendCliHello;
      end;

    hssReadSrvHello,
    hssReadSrvHelloNoRead,
    hssReadSrvHelloContNeed:
      begin
        // Set up the input buffers. Buffer 0 is used to pass in data
        // received from the server. Schannel will consume some or all
        // of this. Leftover data (if any) will be placed in buffer 1 and
        // given a buffer type of SECBUFFER_EXTRA.
        InBuffers[0].cbBuffer   := HandShakeData.cbIoBuffer;
        InBuffers[0].BufferType := SECBUFFER_TOKEN;
        InBuffers[0].pvBuffer   := HandShakeData.IoBuffer;

        InBuffers[1]            := Default(SecBuffer);
        InBuffers[1].BufferType := SECBUFFER_EMPTY;

        InBuffer.ulVersion := SECBUFFER_VERSION;
        InBuffer.cBuffers  := Length(InBuffers);
        InBuffer.pBuffers  := @InBuffers;

        // Set up the output buffers. These are initialized to NULL
        // so as to make it less likely we'll attempt to free random
        // garbage later.
        SetLength(HandShakeData.OutBuffers, 3);
        HandShakeData.OutBuffers[0] := Default(SecBuffer);
        HandShakeData.OutBuffers[0].BufferType := SECBUFFER_TOKEN;
        // ! Usually only one buffer is enough but I experienced rare and random
        // SEC_E_BUFFER_TOO_SMALL and SEC_E_MESSAGE_ALTERED errors on Windows 7/8.
        // Retrying a handshake worked well. According to Internet findings, these
        // errors are caused by SChannel bug with TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
        // and TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 ciphers. While some advice disabling
        // these ciphers or not using TLSv1.2 at all or disable revocation checking,
        // cURL project tries to solve the issue by adding more buffers. This does
        // NOT fix the error completely but hopefully makes it somewhat less frequent...
        HandShakeData.OutBuffers[1] := Default(SecBuffer);
        HandShakeData.OutBuffers[1].BufferType := SECBUFFER_ALERT;
        HandShakeData.OutBuffers[2] := Default(SecBuffer);
        HandShakeData.OutBuffers[2].BufferType := SECBUFFER_EMPTY;

        OutBuffer.ulVersion := SECBUFFER_VERSION;
        OutBuffer.cBuffers  := Length(HandShakeData.OutBuffers);
        OutBuffer.pBuffers  := PSecBuffer(HandShakeData.OutBuffers);

        Result := g_pSSPI.InitializeSecurityContextW(@SessionData.hCreds,
                                                     @HandShakeData.hContext,
                                                     PSecWChar(Pointer(HandShakeData.ServerName)),
                                                     dwSSPIFlags,
                                                     0,          // Reserved
                                                     0,          // Not used with Schannel
                                                     @InBuffer,
                                                     0,          // Reserved
                                                     nil,
                                                     @OutBuffer,
                                                     dwSSPIOutFlags,
                                                     @tsExpiry);

        // If InitializeSecurityContext returned SEC_E_INCOMPLETE_MESSAGE,
        // then we need to read more data from the server and try again.
        if Result = SEC_E_INCOMPLETE_MESSAGE then Exit;

        // Check for fatal error.
        if Failed(Result) then
          raise ErrSecStatus('@ DoClientHandshake @ server hello', 'InitializeSecurityContext', Result);

        case Result of
          // SEC_I_CONTINUE_NEEDED:
          //   - Not enough data provided (seems it should be SEC_E_INCOMPLETE_MESSAGE
          //     but SChannel returns SEC_I_CONTINUE_NEEDED):
          //       * InBuffers[1] contains length of unread buffer that should be
          //         feed to InitializeSecurityContext next time
          //       * OutBuffers contain nothing
          //   - Token must be sent to server
          //       * OutBuffers[1] contains token to be sent
          SEC_I_CONTINUE_NEEDED:
            begin
              HandShakeData.Stage := hssReadSrvHelloContNeed;
            end;
          // SEC_I_INCOMPLETE_CREDENTIALS:
          // the server just requested client authentication.
          SEC_I_INCOMPLETE_CREDENTIALS:
            begin
              Debug(LogPrefix + '!! SEC_I_INCOMPLETE_CREDENTIALS !!');
              // Busted. The server has requested client authentication and
              // the credential we supplied didn't contain a client certificate.
              // This function will read the list of trusted certificate
              // authorities ("issuers") that was received from the server
              // and attempt to find a suitable client certificate that
              // was issued by one of these. If this function is successful,
              // then we will connect using the new certificate. Otherwise,
              // we will attempt to connect anonymously (using our current credentials).
              GetNewClientCredentials(SessionData, HandShakeData.hContext);
              // Go around again
              HandShakeData.Stage := hssReadSrvHelloNoRead;
            end;
          // SEC_E_OK:
          // handshake completed successfully.
          // handle extra data if present and finish the process
          SEC_E_OK:
            begin
              HandShakeData.Stage := hssReadSrvHelloOK;
            end;
          else  // SEC_I_COMPLETE_AND_CONTINUE, SEC_I_COMPLETE_NEEDED
            raise ErrSecStatus('@ DoClientHandshake @ server hello - don''t know how to handle this', 'InitializeSecurityContext', Result);
        end; // case

        HandleBuffers(InBuffers[1]);
      end; // hssReadServerHello*
    else
      raise Error('Error at DoClientHandshake: Stage not handled');
  end; // case
end;

procedure GetShutdownData(const SessionData: TSessionData; const hContext: CtxtHandle;
  out OutBuffer: SecBuffer);
var
  dwType, dwSSPIFlags, dwSSPIOutFlags, Status: DWORD;
  OutBufferDesc: SecBufferDesc;
  OutBuffers: array[0..0] of SecBuffer;
  tsExpiry: TimeStamp;
begin
  OutBuffer := Default(SecBuffer);

  dwType := SCHANNEL_SHUTDOWN; // Notify schannel that we are about to close the connection.

  OutBuffers[0].cbBuffer   := SizeOf(dwType);
  OutBuffers[0].BufferType := SECBUFFER_TOKEN;
  OutBuffers[0].pvBuffer   := @dwType;

  OutBufferDesc.ulVersion := SECBUFFER_VERSION;
  OutBufferDesc.cBuffers  := Length(OutBuffers);
  OutBufferDesc.pBuffers  := @OutBuffers;

  Status := g_pSSPI.ApplyControlToken(@hContext, @OutBufferDesc);
  if Failed(Status) then
    raise ErrSecStatus('@ GetShutdownData', 'ApplyControlToken', Status);

  // Build an SSL close notify message.
  dwSSPIFlags :=
    ISC_REQ_SEQUENCE_DETECT or ISC_REQ_REPLAY_DETECT or ISC_REQ_CONFIDENTIALITY or
    ISC_RET_EXTENDED_ERROR or ISC_REQ_ALLOCATE_MEMORY or ISC_REQ_STREAM;

  OutBuffers[0] := Default(SecBuffer);
  OutBuffers[0].BufferType := SECBUFFER_TOKEN;

  OutBufferDesc.ulVersion := SECBUFFER_VERSION;
  OutBufferDesc.cBuffers  := Length(OutBuffers);
  OutBufferDesc.pBuffers  := @OutBuffers;

  Status := g_pSSPI.InitializeSecurityContextW(@SessionData.hCreds,
                                               @hContext,
                                               nil,
                                               dwSSPIFlags,
                                               0,
                                               SECURITY_NATIVE_DREP,
                                               nil,
                                               0,
                                               @hContext,
                                               @OutBufferDesc,
                                               dwSSPIOutFlags,
                                               @tsExpiry);

  if Failed(Status) then
  begin
    g_pSSPI.FreeContextBuffer(OutBuffers[0].pvBuffer); // Free output buffer.
    raise ErrSecStatus('@ GetShutdownData', 'InitializeSecurityContext', Status);
  end;

  OutBuffer := OutBuffers[0];
end;

procedure VerifyServerCertificate(pServerCert: PCCERT_CONTEXT; const szServerName: string; dwCertFlags: DWORD);
var
  polHttps: HTTPSPolicyCallbackData;
  PolicyPara: CERT_CHAIN_POLICY_PARA;
  PolicyStatus: CERT_CHAIN_POLICY_STATUS;
  ChainPara: CERT_CHAIN_PARA;
  pChainContext: PCCERT_CHAIN_CONTEXT;
const
  rgszUsages: array[0..2] of PAnsiChar = (
    szOID_PKIX_KP_SERVER_AUTH,
    szOID_SERVER_GATED_CRYPTO,
    szOID_SGC_NETSCAPE
  );
  cUsages: DWORD = SizeOf(rgszUsages) div SizeOf(LPSTR);
begin
  pChainContext := nil;

  if pServerCert = nil then
    raise Error('Error @ VerifyServerCertificate - server cert is NULL');

  // Build certificate chain.
  try
    ChainPara := Default(CERT_CHAIN_PARA);
    ChainPara.cbSize := SizeOf(ChainPara);
    ChainPara.RequestedUsage.dwType := USAGE_MATCH_TYPE_OR;
    ChainPara.RequestedUsage.Usage.cUsageIdentifier     := cUsages;
    ChainPara.RequestedUsage.Usage.rgpszUsageIdentifier := PAnsiChar(@rgszUsages);

    if not CertGetCertificateChain(0,
                                   pServerCert,
                                   nil,
                                   pServerCert.hCertStore,
                                   @ChainPara,
                                   0,
                                   nil,
                                   @pChainContext) then
      raise ErrWinAPI('@ VerifyServerCertificate', 'CertGetCertificateChain');

    // Validate certificate chain.
    polHttps := Default(HTTPSPolicyCallbackData);
    polHttps.cbSize         := SizeOf(HTTPSPolicyCallbackData);
    polHttps.dwAuthType     := AUTHTYPE_SERVER;
    polHttps.fdwChecks      := dwCertFlags;
    polHttps.pwszServerName := PChar(szServerName);

    PolicyPara := Default(CERT_CHAIN_POLICY_PARA);
    PolicyPara.cbSize            := SizeOf(PolicyPara);
    PolicyPara.pvExtraPolicyPara := @polHttps;

    PolicyStatus := Default(CERT_CHAIN_POLICY_STATUS);
    PolicyStatus.cbSize := SizeOf(PolicyStatus);

    if not CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_SSL,
                                            pChainContext,
                                            @PolicyPara,
                                            @PolicyStatus) then
      raise ErrWinAPI('@ VerifyServerCertificate', 'CertVerifyCertificateChainPolicy');

    if PolicyStatus.dwError <> NO_ERROR then
      raise Error('Error @ VerifyServerCertificate verifying cert chain calling method "CertVerifyCertificateChainPolicy": %s',
        [WinVerifyTrustErrorStr(PolicyStatus.dwError)]);
  finally
    if pChainContext <> nil then
      CertFreeCertificateChain(pChainContext);
  end;
end;

procedure CheckServerCert(const hContext: CtxtHandle; const ServerName: string);
var
  Status: SECURITY_STATUS;
  pRemoteCertContext: PCCERT_CONTEXT;
begin
  pRemoteCertContext := nil;
  // Authenticate server's credentials. Get server's certificate.
  Status := g_pSSPI.QueryContextAttributesW(@hContext, SECPKG_ATTR_REMOTE_CERT_CONTEXT, @pRemoteCertContext);
  if Status <> SEC_E_OK then
    raise ErrSecStatus('@ CheckServerCert', 'QueryContextAttributesW', Status);

  try
    // Attempt to validate server certificate.
    VerifyServerCertificate(pRemoteCertContext, ServerName, 0);
  finally
    // Free the server certificate context.
    CertFreeCertificateContext(pRemoteCertContext);
  end;
end;

procedure DeleteContext(var hContext: CtxtHandle);
begin
  g_pSSPI.DeleteSecurityContext(@hContext);
  hContext := Default(CtxtHandle);
end;

// ~~ Data exchange ~~

procedure InitBuffers(const hContext: CtxtHandle; out pbIoBuffer: TBytes;
  out Sizes: SecPkgContext_StreamSizes);
var
  scRet: SECURITY_STATUS;
begin
  // Read stream encryption properties.
  scRet := g_pSSPI.QueryContextAttributesW(@hContext, SECPKG_ATTR_STREAM_SIZES, @Sizes);
  if scRet <> SEC_E_OK then
    raise ErrSecStatus('@ InitBuffers', 'QueryContextAttributesW', scRet);
  // Create a buffer.
  SetLength(pbIoBuffer, Sizes.cbHeader + Sizes.cbMaximumMessage + Sizes.cbTrailer);
end;

procedure EncryptData(const hContext: CtxtHandle; const Sizes: SecPkgContext_StreamSizes;
  pbMessage: PByte; cbMessage: DWORD; pbIoBuffer: PByte; pbIoBufferLength: DWORD;
  out cbWritten: DWORD);
var
  scRet: SECURITY_STATUS;
  Msg: SecBufferDesc;
  Buffers: array[0..3] of SecBuffer;
begin
  if cbMessage > Sizes.cbMaximumMessage then
    raise Error('Message size %d is greater than maximum allowed %d', [cbMessage, Sizes.cbMaximumMessage]);

  if pbIoBufferLength < Sizes.cbHeader + cbMessage + Sizes.cbTrailer then
    raise Error('Buffer size %d is lesser than required for message with length %d', [pbIoBufferLength, cbMessage]);

  Move(pbMessage^, (pbIoBuffer + Sizes.cbHeader)^, cbMessage); // Offset by "header size"
  pbMessage := (pbIoBuffer + Sizes.cbHeader); // pointer to copy of message

  // Encrypt the data
  Buffers[0].cbBuffer   := Sizes.cbHeader;           // length of header
  Buffers[0].BufferType := SECBUFFER_STREAM_HEADER;  // Type of the buffer
  Buffers[0].pvBuffer   := pbIoBuffer;               // Pointer to buffer 1

  Buffers[1].cbBuffer   := cbMessage;                // length of the message
  Buffers[1].BufferType := SECBUFFER_DATA;           // Type of the buffer
  Buffers[1].pvBuffer   := pbMessage;                // Pointer to buffer 2

  Buffers[2].cbBuffer   := Sizes.cbTrailer;          // length of the trailer
  Buffers[2].BufferType := SECBUFFER_STREAM_TRAILER; // Type of the buffer
  Buffers[2].pvBuffer   := pbMessage + cbMessage;    // Pointer to buffer 3

  Buffers[3]            := Default(SecBuffer);
  Buffers[3].BufferType := SECBUFFER_EMPTY;          // Type of the buffer 4

  Msg.ulVersion   := SECBUFFER_VERSION;  // Version number
  Msg.cBuffers    := Length(Buffers);    // Number of buffers - must contain four SecBuffer structures.
  Msg.pBuffers    := @Buffers;           // Pointer to array of buffers
  scRet := g_pSSPI.EncryptMessage(@hContext, 0, @Msg, 0); // must contain four SecBuffer structures.
  if Failed(scRet) then
    raise ErrSecStatus('@ EncryptData', 'EncryptMessage', scRet);

  // Resulting Buffers: header, data, trailer
  cbWritten := Buffers[0].cbBuffer + Buffers[1].cbBuffer + Buffers[2].cbBuffer;
  if cbWritten = 0 then
    raise Error('EncryptData: zero data');
end;

function DecryptData(const hContext: CtxtHandle; const Sizes: SecPkgContext_StreamSizes;
  pbIoBuffer: PByte; var cbEncData: DWORD;
  pbDecData: PByte; cbDecDataLength: DWORD; out cbWritten: DWORD): SECURITY_STATUS;
var
  Msg: SecBufferDesc;
  Buffers: array[0..3] of SecBuffer;
  i, DataBufferIdx, ExtraBufferIdx: Integer;
  cbCurrEncData: DWORD;
  pbCurrIoBuffer: PByte;
  Dummy: Cardinal;
begin
  cbWritten := 0;

  cbCurrEncData := cbEncData;
  pbCurrIoBuffer := pbIoBuffer;

  // Decrypt the received data.
  repeat
    Buffers[0].cbBuffer   := cbCurrEncData;
    Buffers[0].BufferType := SECBUFFER_DATA;  // Initial Type of the buffer 1
    Buffers[0].pvBuffer   := pbCurrIoBuffer;
    Buffers[1]            := Default(SecBuffer);
    Buffers[1].BufferType := SECBUFFER_EMPTY; // Initial Type of the buffer 2
    Buffers[2]            := Default(SecBuffer);
    Buffers[2].BufferType := SECBUFFER_EMPTY; // Initial Type of the buffer 3
    Buffers[3]            := Default(SecBuffer);
    Buffers[3].BufferType := SECBUFFER_EMPTY; // Initial Type of the buffer 4

    Msg.ulVersion := SECBUFFER_VERSION;  // Version number
    Msg.cBuffers  := Length(Buffers);    // Number of buffers - must contain four SecBuffer structures.
    Msg.pBuffers  := @Buffers;           // Pointer to array of buffers
    Result := g_pSSPI.DecryptMessage(@hContext, @Msg, 0, Dummy);

    if Result = SEC_I_CONTEXT_EXPIRED then
      Break; // Server signaled end of session

    if (Result <> SEC_E_OK) and
       (Result <> SEC_E_INCOMPLETE_MESSAGE) and
       (Result <> SEC_I_RENEGOTIATE) then
      raise ErrSecStatus('@ DecryptData - unexpected result', 'DecryptMessage', Result);

    // After DecryptMessage data is still in the Buffers
    // Buffer with type DATA contains decrypted data
    // Buffer with type EXTRA contains remaining (unprocessed) data
    DataBufferIdx := 0;
    ExtraBufferIdx := 0;
    for i := Low(Buffers) to High(Buffers) do
      case Buffers[i].BufferType of
        SECBUFFER_DATA : DataBufferIdx := i;
        SECBUFFER_EXTRA: ExtraBufferIdx := i;
      end;

    if Result = SEC_E_INCOMPLETE_MESSAGE then
    begin
      Assert(DataBufferIdx = 0);
      Assert(ExtraBufferIdx = 0);
      // move remaining extra data to the beginning of buffer and exit
      Move(pbCurrIoBuffer^, pbIoBuffer^, cbCurrEncData);
      cbEncData := cbCurrEncData;
      Break;
    end;

    // Move received data to destination if present
    if DataBufferIdx <> 0 then
    begin
      // check output buf space remaining
      if cbDecDataLength < Buffers[DataBufferIdx].cbBuffer then
        Break;
      Move(Buffers[DataBufferIdx].pvBuffer^, pbDecData^, Buffers[DataBufferIdx].cbBuffer);
      Inc(pbDecData, Buffers[DataBufferIdx].cbBuffer);
      Inc(cbWritten, Buffers[DataBufferIdx].cbBuffer);
      Dec(cbDecDataLength, Buffers[DataBufferIdx].cbBuffer);
    end
    // No data decrypted - move remaining extra data to the beginning of buffer and exit
    else
    begin
      if ExtraBufferIdx <> 0 then
      begin
        Move(Buffers[ExtraBufferIdx].pvBuffer^, pbIoBuffer^, Buffers[ExtraBufferIdx].cbBuffer);
        cbEncData := Buffers[ExtraBufferIdx].cbBuffer;
      end
      else
        cbEncData := 0; // all data processed
      Break;
    end;

    // Move pointers to the extra buffer to process it in the next iteration
    if ExtraBufferIdx <> 0 then
    begin
      pbCurrIoBuffer := Buffers[ExtraBufferIdx].pvBuffer;
      cbCurrEncData := Buffers[ExtraBufferIdx].cbBuffer;
    end
    // No unprocessed data - break the loop
    else
    begin
      cbEncData := 0; // all data processed
      Break;
    end;

    // The server wants to perform another handshake sequence.
    if Result = SEC_I_RENEGOTIATE then
      Break;
  until False;
end;

initialization

finalization
  Fin;

{$ENDIF MSWINDOWS}
end.
