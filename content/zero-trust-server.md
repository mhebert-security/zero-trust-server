# zero-trust-server

The server that answers this request is not nginx and not a framework. It is
a hand-rolled HTTP/1.1 stack on raw TCP sockets, rustls for TLS 1.3, and a
proof of work gate in front of every page, all in one Rust binary you can
read end to end.

## why build it

A claim like "I know what this server does" is only worth what you can check.
The usual answer is a box you trust on faith, a pile of dependencies, and a
patch treadmill. This project answers with the opposite: the whole serving
path is small enough to hold, the cryptographic core is written from the
specs, and every page you read is served by code with no secret you cannot
rotate.

The stack is deliberately bare. HTTP/1.1 parsing and response framing are
written here, SHA-256 and HMAC-SHA256 are written here from the FIPS
vectors, and TLS 1.3 is handled by rustls, the library that exists so the
TLS you ship is the TLS that is reviewed. Fewer layers is not fewer
features; it is fewer places for a mismatch to hide.

## how the gate works

Before any page is served, a visitor solves a proof of work puzzle whose
answer is a SHA-256 digest with a fixed number of leading zero bits. A
correct solution earns a session cookie signed with an HMAC built on the
hand-written SHA-256. The cookie is a pass or fail, and it is the only
identity the server needs.

The gate prices a request in CPU before the server spends anything on it.
That makes the pages behind it expensive to scrape at line rate, which is
the point for a site that publishes its source and wants readers, not a
harvesting loop.

## what ships verified

The crypto module carries differential property tests against an
independent implementation, plus a clean run under MIRI, the interpreter
that checks for undefined behavior. Consumed nonces are rejected, so a
captured puzzle answer cannot be replayed. The admin login is throttled per
IP and its failure path runs in constant time.

The TLS configuration pins a hybrid post-quantum key exchange,
X25519MLKEM768, so a captured handshake cannot later fall to a classical
computer. The negotiation is locked by tests that run a real handshake over
loopback, and a probe binary checks the live deployment from the wire.

## what "zero trust" means here

The current design is a gate and a pass or fail cookie. That is a beginning,
not a destination. The shape the code leans toward is attestations with no
central authority, a session that is a signed set of permissions, and a
cryptographic core small enough that a proof assistant can check it.

None of that is a roadmap written on faith. Every step lands in this repo,
tested and public, so the distance between the name and the code is visible
the whole way.

## links

The source lives at
[github.com/mhebert-security/zero-trust-server](https://github.com/mhebert-security/zero-trust-server),
with the changelog, the design decisions, and the audit trail that made
each one. The [transparency page](/transparency) records what the server
keeps and what it never does.
