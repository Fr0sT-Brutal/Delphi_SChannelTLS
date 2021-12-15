Notable changes
===============

## Current

- [+] (API) TTrustedCerts, MT-safe; added .Contains(Host) method to check if there's any chance a cert for the host could be in the list. .Count method removed.
- [+] (API) SChannel.Utils.pas: + CheckServerCert, returns result code allowing caller to determine why cert was considered valid
- [+] (API) SChannel.Utils.pas: TSessionData.ServerName - add this field because session is 1:1 related to domain name.
- [+] (API) SChannel.Utils.pas: TTLSOptions - Base class for shared TLS options storage
- [+] (API) SChannel.Utils.pas: CheckServerCert overload with TSessionData argument
- [+] (API) SChannel.Utils.pas: GetCurrentCert for more convenient server cert retrieval without too much of specific stuff
- [*] (API) SChannel.Utils.pas: Error messages include localized texts and status value in hex to make search easier
- [*] (API) SChannel.Utils.pas: CreateCredentials, sets SCH_CRED_IGNORE_REVOCATION_OFFLINE flag (if CRL is unavailable, we likely want to connect anyway)
- [+] (API) SChannel.Utils.pas: * Redesign of DebugLog functions. Move TDefaultDebugFnHoster and Debug to intf section, deprecate TSessionData.DebugFn field, add DebugLogFn argument to DoClientHandshake.
- [*] (API) SChannel.Utils.pas: Deprecate THandShakeData.ServerName in favor of TSessionData.ServerName
- [*] IcsSChannelSocket.pas: + Use logging method during handshake so details are reported to log
- [+] Demo: Print cert data, Manual cert check for sync request

## 23.11.2021

- [+] (API) + More control over server cert validation: flags to allow ignoring some cert aspects and list of trusted certs that are considered valid without any check. SChannel.Utils.pas: add TrustedCerts and CertCheckIgnoreFlags fields to TSessionData. CheckServerCert, added optional TrustedCerts and CertCheckIgnoreFlags parameters.
- [*] SChannel.Utils.pas: DoClientHandshake, enables sfNoServerVerify flag if either TrustedCerts or CertCheckIgnoreFlags is not empty in SessionData
- [*] (API) SChannel.Utils.pas: ESSPIError.CreateSecStatus, overloaded version removed as it didn't use SecStatus field. United method accepts both SecStatus and optional custom info
- [+] IcsSChannelSocket.pas: TSChannelWSocket.DoHandshakeSuccess, use SessionData's TrustedCerts and CertCheckIgnoreFlags fields; report exceptions with loSslErr level before reraising
- [*] TSChannelWSocket.DoHandshakeProcess, WSAEWOULDBLOCK is ignored and other errors are reported with loSslErr level
- [+] Demo: Options to check cert manually, ability to set cert props to ignore, option to dump cert after handshake

## 25.03.2021

- [+] (API) SyncHandshake: RecvFn, SendFn could return < 0 error codes that will be reported to log
- [+] Support checking of server cert when its address is IP in utils, TSChannelWSocket and Demo
- [+] (API) SChannel.Utils.pas: extract default SSPI flags into constant and allow user to override it with TSessionData.SSPIFlags
- [+] (API) Add TSessionData.DebugFn callback to report events from within DoClientHandshake
- [+] (API) SChannel.Utils.pas: add CreateSharedCreds factory function
- [*] (BREAKING, API) SyncHandshake: TRecvFn & TSendFn are object methods to get rid of `Data` argument
- [*] (BREAKING, API) Session data rework. Extract credentials to separate record that could be shared and leave session options personal. TSChannelWSocket.SharedSessionData => SessionData, it now stores writeable session record
- [!] TSChannelWSocket.DoRecv, empty Receive to re-launch FD_READ event wasn't working. Introduced imitation of the event by posting a message (method that uses ICS itself) with method PostFD_EVENT
- [!] Fix app crash if DoClientHandshake raises exception
- [*] (API) SChannel.Utils.pas, patterns in S_Msg_HShStage*Fail messages include %d and %s placeholders; S_Msg_HShStageW1Incomplete and S_Msg_HShStageW2Incomplete added
- [*] (API) SChannel.SyncHandshake.pas, PerformClientHandshake raises new EHandshakeCommError on communication failure to distinguish SChannel-level errors from recv/send failures
- [!] IcsSChannelSocket.pas: Fix TLS connection over proxy. HTTP tunnel support requires change in ICS TWSocket class (at least ICS V8.66 - Part 10 or manual modification of ICS source needed)

## 29.10.2020

- [+] Sync handshake handles extra data that server could send


## 16.01.2020

- [*] GetNewClientCredentials doesn't raise exception if no certificate chain found
- [+] IcsSChannelSocket support TLS channel starting/finishing at any moment by setting `Secure` property; OnTLSDone and OnTLSShutdown events added
- [+] Add session flags (TSessionData.Flags), currently only one option to bypass server cert verification (sfNoServerVerify)
- [+] ISharedSessionData and TSharedSessionData to share credentials between connections
- [+] IcsSChannelSocket supports sharing of session data

