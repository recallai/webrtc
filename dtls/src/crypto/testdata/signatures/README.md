# Signature verification fixtures

`teams-p384.der`, `teams-p384-sha256.sig`, and `teams-key-exchange.bin` are
public handshake data from the 2026-09-09 Teams failure. Frames 1468 and 1470
provide the client/server randoms, server certificate, ECDHE parameters,
and ServerKeyExchange signature. The signed message is:

```
client_random || server_random || 03 || 0017 || 41 || server_ecdh_public_key
```

The signing key is P-384; the ephemeral ECDHE key is P-256. The signature hash
is SHA-256. These different curves are intentional. OpenSSL independently
verified the signature. The original verifier fails with
`ring::error::Unspecified`; selecting P-384/SHA-256 succeeds.

The remaining fixtures use synthetic P-256 and P-384 certificates and
SHA-256/SHA-384 signatures over `message.bin`, generated with OpenSSL.
No private keys, session secrets, or application data are included. Certificate
validity dates do not affect these tests: they test handshake signatures,
not certificate chain validation.

To generate equivalent synthetic fixtures (in a temporary directory):

```sh
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 -out key.pem
openssl req -new -x509 -key key.pem -subj '/CN=DTLS regression test' -days 3650 -outform DER -out p256.der
openssl dgst -sha256 -sign key.pem -out p256-sha256.sig message.bin
openssl dgst -sha384 -sign key.pem -out p256-sha384.sig message.bin
```

Repeat with `secp384r1` and the `p384` prefix, then discard the private keys.

Run the regression and compatibility checks:

```sh
cargo test -p dtls --locked --features pem
cargo test -p dtls --test openssl_interop --locked --features pem -- --ignored --nocapture
```

The OpenSSL test requires a Unix host and OpenSSL 3 on PATH. It checks full
DTLS handshakes, encrypted application data, and SRTP profile negotiation for
both curves, both hashes, and all three SRTP profiles offered by the bot.
