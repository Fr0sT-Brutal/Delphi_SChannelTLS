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

3. `TSChannelWSocket` class from `IcsSChannelSocket.pas` already implements one-time retrying invisibly to a caller.
