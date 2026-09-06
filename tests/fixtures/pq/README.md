# Post-quantum TLS test fixtures

A throwaway CA and a localhost leaf used by the handshake regression tests in
`src/tls.rs`. They exist so a full TLS 1.3 handshake can run against the real
`load_config` path over loopback without trusting a network host.

The private key (`server-key.pem`) authenticates nothing real. It signs
nothing and gates no service; it is public test material, committed so the
tests run without a build step or a new dependency. Treat it as disposable.

Regenerate any time with openssl (EC P-256):

```
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out ca-key.pem
openssl req -x509 -new -key ca-key.pem -sha256 -days 3650 \
  -subj "/CN=PQ Test CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" -out ca-cert.pem
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out server-key.pem
openssl req -new -key server-key.pem -subj "/CN=localhost" -out server.csr
printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost\n' > ext.cnf
openssl x509 -req -in server.csr -CA ca-cert.pem -CAkey ca-key.pem \
  -CAcreateserial -days 3650 -sha256 -extfile ext.cnf -out server-cert.pem
```

The client in the tests trusts `ca-cert.pem`; the server presents
`server-cert.pem` and `server-key.pem`.
