Delphi SChannel (TLS with WinAPI)
---------------------------------

SChannel is Windows built-in implementation of TLS protocols. This allows supporting secure connections without any external library.

Repo contains:

- [`SChannel.Utils.pas`](https://fr0st-brutal.github.io/Delphi_SChannelTLS/docs/SChannel.Utils.html) - unit with transport-agnostic helper functions for easy implementation of TLS communication by means of Windows SChannel.
  
- [`SChannel.SyncHandshake.pas`](https://fr0st-brutal.github.io/Delphi_SChannelTLS/docs/SChannel.SyncHandshake.html) - sample of transport-agnostic synchronous TLS handshake using callback functions for real communication

- `Jwa*.pas` - API declarations borrowed from JEDI project

- [`IcsSChannelSocket.pas`](https://fr0st-brutal.github.io/Delphi_SChannelTLS/docs/IcsSChannelSocket.html) - [ICS](http://www.overbyte.eu/frame_index.html) TWSocket descendant that performs TLS communication

- `Demo\` - demo project for performing any textual (mainly HTTPS) requests via secure connection

- `Enable TLS 1.1 and 1.2 for W7.reg` - registry patch that enables TLS 1.1 and 1.2 on Windows 7 (these are actual protocol versions that are not enabled by default on W7)

Developer note
--------------

This project was started because I needed TLS in my Delphi apps and didn't like shipping two OpenSSL libs. Initial version was 1:1 rewrite of SChannel sample found in Internet. Currently it is used in my 24*7 projects but I implemented only those functions which I needed. I'm not familiar with all this cryptostuff so don't expect advanced certificate validations, secure servers and so on. But if you wish to add something missing I'll consider your PR with pleasure :).

Note - SChannel bug
-------------------

There's SChannel bug that causes functions rarely and randomly return `SEC_E_BUFFER_TOO_SMALL` or `SEC_E_MESSAGE_ALTERED` status during handshake. Good description of the issue could be found [here](https://github.com/Waffle/waffle/pull/128#issuecomment-163342222) (in brief: it only happens on Windows 7 and 8, with TLSv1.2 and `TLS_DHE_RSA_WITH_AES_128_GCM_SHA256` and `TLS_DHE_RSA_WITH_AES_256_GCM_SHA384` cipher suites). To deal with the issue, several measures were taken:

1. Increased number of buffers for handshake (what cURL team did) - didn't help
2. Added function `IsWinHandshakeBug` to `SChannel.Utils.pas` that allows to conveniently check for the bug in `except` section of a `DoClientHandshake` call. Just a helper to make special processing like

	```pascal
	...
	try
	  DoClientHandshake(FSessionData, FHandShakeData);
	except on E: ESSPIError do
	  // Hide Windows handshake bug and restart the process
	  if (FHandShakeData.Stage = hssReadSrvHello) and IsWinHandshakeBug(E.SecStatus) then
	  begin
	    Log(Format('Handshake bug: "%s", retrying', [E.Message]));
	    DeleteContext(FHandShakeData.hContext);
	    DoHandshakeStart;
	    Exit;
	  end
	  else
	    raise E;
	end;
	...
	```

3. `TSChannelWSocket` class from `IcsSChannelSocket.pas` and `PerformClientHandshake` function from `SChannel.SyncHandshake.pas` already implement one-time retrying invisibly to a caller.

IcsSChannelSocket
-------------------

Socket class descending from [ICS](http://www.overbyte.eu/frame_index.html) `TWSocket` that does many things for you. Key features:

- Automatic handshake retry when handshake bug (see above) is encountered
- TLS channel could be started/finished at any moment by setting `Secure` property; `OnTLSDone` and `OnTLSShutdown` events will signal channel state
- Session data could be shared between multiple sockets with `SharedSessionData` property. When sessions are shared, handshake becomes significantly shorter so it worths it