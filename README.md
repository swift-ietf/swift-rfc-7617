# swift-rfc-7617

Use this package when you send or check HTTP Basic credentials, or issue the challenge that asks for them. Start from `RFC_7617.Basic` for the `Authorization` value and `RFC_7617.Basic.Challenge` for the `WWW-Authenticate` value. If you only need to find the token in a header without decoding it, use `RFC_7617.Basic.Parse`. For bearer tokens, use swift-rfc-6750.

## Laws

- Credentials are written as `Basic`, a space, and the Base64 of the user-id, a colon and the password, encoded as UTF-8. The Aladdin example of RFC 7617 gives `Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==`.
- The scheme name is read without regard to case, so `basic` is accepted. It is always written as `Basic`.
- A user-id may not contain a colon. A password may, because reading splits the decoded text at the first colon. Either one may be empty.
- `RFC_7617.Basic.Challenge` accepts no charset other than UTF-8, in any case.
- Reading a challenge requires a realm. Values may be quoted or bare. Inside quotes a comma belongs to the value and a backslash escape is undone.
- A challenge is always written with the realm quoted, and `"` and `\` in the realm escaped by a backslash. The charset follows only when one was given.
- `RFC_7617.Basic.Parse` does not decode the Base64. It skips any spaces after the scheme, takes the token68 with its trailing `=` padding, and leaves the rest of the input unread.
