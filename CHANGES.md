Notable changes
===============

## 16.01.2020

- [*] GetNewClientCredentials doesn't raise exception if no certificate chain found
- [+] IcsSChannelSocket support TLS channel starting/finishing at any moment by setting `Secure` property; OnTLSDone and OnTLSShutdown events added
- [+] Add session flags (TSessionData.Flags), currently only one option to bypass server cert verification (sfNoServerVerify)
- [+] ISharedSessionData and TSharedSessionData to share credentials between connections
- [+] IcsSChannelSocket supports sharing of session data

