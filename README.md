Delphi SChannel (TLS with WinAPI)
---------------------------------

SChannel is Windows built-in implementation of TLS protocols. This allows supporting secure connections without any external library.

Repo contains:

- [`SChannel.Utils.pas`](https://fr0st-brutal.github.io/Delphi_SChannelTLS/SChannel.Utils.html) - unit with transport-agnostic helper functions for easy implementation of TLS communication by means of
  Windows SChannel.
  
- [`SChannel.SyncHandshake.pas`](https://fr0st-brutal.github.io/Delphi_SChannelTLS/SChannel.SyncHandshake.html) - sample of transport-agnostic synchronous TLS handshake using callback functions for real communication

- `Jwa*.pas` - API declarations borrowed from JEDI project

- `IcsSChannelSocket.pas` - [ICS](http://www.overbyte.eu/frame_index.html) TWSocket descendant that performs TLS communication

- `Demo\` - demo project for performing any textual (mainly HTTPS) requests via secure connection

- `Enable TLS 1.1 and 1.2 for W7.reg` - registry patch that enables TLS 1.1 and 1.2 on Windows 7 (these are actual protocol versions that are not enabled by default on W7)