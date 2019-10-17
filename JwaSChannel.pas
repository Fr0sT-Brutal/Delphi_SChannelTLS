{******************************************************************************}
{                                                                              }
{ SChannel API definitions for Object Pascal                                   }
{                                                                              }
{******************************************************************************}

unit JwaSChannel;

interface

uses
  Windows, JwaBaseTypes, JwaWinCrypt;

const
// Protocols
  SP_PROT_TLS1_0_SERVER = $00000040;
  SP_PROT_TLS1_0_CLIENT = $00000080;
  SP_PROT_TLS1_0        = SP_PROT_TLS1_0_SERVER or SP_PROT_TLS1_0_CLIENT;

  SP_PROT_TLS1_1_SERVER = $00000100;
  SP_PROT_TLS1_1_CLIENT = $00000200;
  SP_PROT_TLS1_1        = SP_PROT_TLS1_1_SERVER or SP_PROT_TLS1_1_CLIENT;

  SP_PROT_TLS1_2_SERVER = $00000400;
  SP_PROT_TLS1_2_CLIENT = $00000800;
  SP_PROT_TLS1_2        = SP_PROT_TLS1_2_SERVER or SP_PROT_TLS1_2_CLIENT;

// QueryContextAttributes/QueryCredentialsAttribute extensions
  SECPKG_ATTR_REMOTE_CERT_CONTEXT  = $53;  // returns PCCERT_CONTEXT
  SECPKG_ATTR_LOCAL_CERT_CONTEXT   = $54;  // returns PCCERT_CONTEXT
  SECPKG_ATTR_ROOT_STORE           = $55;  // returns HCERTCONTEXT to the root store
  SECPKG_ATTR_SUPPORTED_ALGS       = $56;  // returns SecPkgCred_SupportedAlgs
  SECPKG_ATTR_CIPHER_STRENGTHS     = $57;  // returns SecPkgCred_CipherStrengths
  SECPKG_ATTR_SUPPORTED_PROTOCOLS  = $58;  // returns SecPkgCred_SupportedProtocols
  SECPKG_ATTR_ISSUER_LIST_EX       = $59;  // returns SecPkgContext_IssuerListInfoEx
  SECPKG_ATTR_CONNECTION_INFO      = $5a;  // returns SecPkgContext_ConnectionInfo

  UNISP_NAME = 'Microsoft Unified Security Protocol Provider';

//
//
// ApplyControlToken PkgParams types
//
// These identifiers are the DWORD types
// to be passed into ApplyControlToken
// through a PkgParams buffer.
  SCHANNEL_RENEGOTIATE = 0;   // renegotiate a connection
  SCHANNEL_SHUTDOWN    = 1;   // gracefully close down a connection
  SCHANNEL_ALERT       = 2;   // build an error message
  SCHANNEL_SESSION     = 3;   // session control

//
// Schannel credentials data structure.
//
  SCH_CRED_V1           = $00000001;
  SCH_CRED_V2           = $00000002;  // for legacy code
  SCH_CRED_VERSION      = $00000002;  // for legacy code
  SCH_CRED_V3           = $00000003;  // for legacy code
  SCHANNEL_CRED_VERSION = $00000004;

type
  _SCHANNEL_CRED = record
    dwVersion: DWORD;       // always SCHANNEL_CRED_VERSION
    cCreds: DWORD;
    paCred: PCCERT_CONTEXT;
    hRootStore: HCERTSTORE;
    cMappers: DWORD;
    aphMappers: Pointer;    //struct _HMAPPER;
    cSupportedAlgs: DWORD;
    palgSupportedAlgs: ^ALG_ID;
    grbitEnabledProtocols: DWORD;
    dwMinimumCipherStrength: DWORD;
    dwMaximumCipherStrength: DWORD;
    dwSessionLifespan: DWORD;
    dwFlags: DWORD;
    dwCredFormat: DWORD;
  end;
  SCHANNEL_CRED = _SCHANNEL_CRED;
  PSCHANNEL_CRED = ^SCHANNEL_CRED;

type
  SecPkgContext_IssuerListInfoEx = record
    aIssuers: PCERT_NAME_BLOB;
    cIssuers: Cardinal;
  end;

const
  SCH_CRED_NO_SYSTEM_MAPPER                    = $00000002;
  SCH_CRED_NO_SERVERNAME_CHECK                 = $00000004;
  SCH_CRED_MANUAL_CRED_VALIDATION              = $00000008;
  SCH_CRED_NO_DEFAULT_CREDS                    = $00000010;
  SCH_CRED_AUTO_CRED_VALIDATION                = $00000020;
  SCH_CRED_USE_DEFAULT_CREDS                   = $00000040;
  SCH_CRED_DISABLE_RECONNECTS                  = $00000080;
  SCH_CRED_REVOCATION_CHECK_END_CERT           = $00000100;
  SCH_CRED_REVOCATION_CHECK_CHAIN              = $00000200;
  SCH_CRED_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT = $00000400;
  SCH_CRED_IGNORE_NO_REVOCATION_CHECK          = $00000800;
  SCH_CRED_IGNORE_REVOCATION_OFFLINE           = $00001000;
  SCH_CRED_RESTRICTED_ROOTS                    = $00002000;
  SCH_CRED_REVOCATION_CHECK_CACHE_ONLY         = $00004000;
  SCH_CRED_CACHE_ONLY_URL_RETRIEVAL            = $00008000;
  SCH_CRED_MEMORY_STORE_CERT                   = $00010000;
  SCH_CRED_CACHE_ONLY_URL_RETRIEVAL_ON_CREATE  = $00020000;
  SCH_SEND_ROOT_CERT                           = $00040000;

implementation

end.