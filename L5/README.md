# Lecture 5

- [ECDSA_nonce_reuse_template](ECDSA_nonce_reuse_template/): ECDSA over P-256 with deterministic and randomized signing, and a template for the nonce reuse attack.
- [X509_demo](X509_demo/): Read a certificate file and print its X.509 fields.

## ECDSA nonce reuse

```bash
cd ECDSA_nonce_reuse_template
cargo test
cargo run
```

Implement `src/attack.rs`. It compiles, but tests involving unfinished functions fail at `todo!()` until you implement them. Deterministic and randomized ECDSA signing are shown in [Lecture 4](../L4/)'s Signature_demo.

## Certificates

X509_demo asks for a certificate file (PEM or DER) and prints its fields: subject, issuer, validity, public key, signature algorithm, extensions, and SHA-256 fingerprint. A PEM file may hold several certificates; each is printed.

Two examples are in `certs/`:

- `letsencrypt_org_chain.pem`: the chain letsencrypt.org sent in a TLS handshake, leaf first. The leaf has a P-256 key and is valid until 1 February 2027.
- `isrg_root_x1.pem`: the root ISRG Root X1 from the macOS trust store. Subject and issuer are the same: it is self-signed. Servers do not send the root; the client already trusts it.

```bash
cd X509_demo
cargo run
```

To save another site's chain:

```bash
openssl s_client -connect example.com:443 -servername example.com -showcerts </dev/null \
  | awk '/BEGIN CERTIFICATE/,/END CERTIFICATE/' > certs/example_com_chain.pem
```
