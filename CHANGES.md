Notable changes
===============

##

- [+] (API) SyncHandshake: RecvFn, SendFn could return < 0 error codes that will be reported to log
- [+] Support checking of server cert when its address is IP in utils, TSChannelWSocket and Demo
- [+] (API) SChannel.Utils.pas: extract default SSPI flags into constant and allow user to override it with TSessionData.SSPIFlags
- [+] (API) Add TSessionData.DebugFn callback to report events from within DoClientHandshake
- [+] (API) SChannel.Utils.pas: add CreateSharedCreds factory function
- [*] (BREAKING, API) SyncHandshake: TRecvFn & TSendFn are object methods to get rid of `Data` argument
- [*] (BREAKING, API) Session data rework. Extract credentials to separate record that could be shared and leave session options personal. TSChannelWSocket.SharedSessionData => SessionData, it now stores writeable session record
- [!] TSChannelWSocket.DoRecv, empty Receive to re-launch FD_READ event wasn't working. Introduced imitation of the event by posting a message (method that uses ICS itself) with method PostFD_EVENT
- [!] Fix app crash if DoClientHandshake raises exception


## 29.10.2020

- [+] Sync handshake handles extra data that server could send


## 16.01.2020

- [*] GetNewClientCredentials doesn't raise exception if no certificate chain found
- [+] IcsSChannelSocket support TLS channel starting/finishing at any moment by setting `Secure` property; OnTLSDone and OnTLSShutdown events added
- [+] Add session flags (TSessionData.Flags), currently only one option to bypass server cert verification (sfNoServerVerify)
- [+] ISharedSessionData and TSharedSessionData to share credentials between connections
- [+] IcsSChannelSocket supports sharing of session data

