# keymaster

keymaster is a library that enables using crypto currency keys in public key infrastructure roles.

## Design principles

- No internal structures, all values passed are buffers / strings interpretable by OpenSSL (hex, PEM, etc.)
- Each instance of class keymaster is associated with a single private key
- Certificates default to self-signed
  - [Issuer Name Field includes SLIP-0044 index / symbol](https://github.com/satoshilabs/slips/blob/master/slip-0044.md)
  - Can sign, set up chain if needed

## Other Libraries

[js-x25519](https://github.com/CryptoEsel/js-x25519)

[tink](https://github.com/google/tink)

[TweetNaCl](https://tweetnacl.cr.yp.to/software.html)

[tweetnacl-js](https://github.com/dchest/tweetnacl-js)

[blue-crypt](https://git.rootprojects.org/root/acme.js)

[node-forge](https://github.com/digitalbazaar/forge)

## Issues

- [ ] [Node-Forge](https://github.com/digitalbazaar/forge/issues/532)
- [ ] [PKI.js](https://github.com/PeculiarVentures/PKI.js/pull/230)

## TODO

- [x] [Create certificate store](https://www.openssl.org/docs/man1.1.1/man3/X509_STORE_CTX_free.html)
- [x] Create X509 certificate
- [x] Pass in CSR and private key, CA cert and private key
  - [x] Create X509 certificate
  - [x] Copy CSR public key
  - [x] Sign with CA private key
  - [x] Copy over CSR attributes
  - [x] Embed CA cert
  - [x] Embed private key associated with CSR
- [ ] Support [more formats](https://www.openssl.org/docs/man1.1.1/man3/PEM_write_bio_PUBKEY.html) in PEM than just embedded base64
- [ ] Consider making the SKI the wallet address
