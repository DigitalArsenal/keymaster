# KEYMASTER

Keymaster is a library for using cryptocurrency keys in public key infrastructure roles.

## Background

Established Public Key Infrastructure (PKI) architectures with centralized Certificate Authorities (CA) in general do not interoperate well with newer decentralized PKI software like [Bitcoin](https://bitcoin.org/en/).

Specifically, legacy PKI certificate formats like [x.509 v3](https://tools.ietf.org/html/rfc5280) are not easily interoperable with newer key management formats such as [Wallet Import Format (WIF)](https://en.bitcoin.it/wiki/Wallet_import_format) and [seed phrases](https://en.bitcoin.it/wiki/Seed_phrase#:~:text=A%20seed%20phrase%2C%20seed%20recovery,write%20it%20down%20on%20paper.).

This library enables the user to do PKI tasks, such as creating / signing certificates, using private keys that can also be used in newer decentralized software.

## Usage: [API Docs](./dist/doc.md)

## Installation

```
npm i @digitalarsenal.io/keymaster
```

## Other Libraries

[js-x25519](https://github.com/CryptoEsel/js-x25519)

[tink](https://github.com/google/tink)

[TweetNaCl](https://tweetnacl.cr.yp.to/software.html)

[tweetnacl-js](https://github.com/dchest/tweetnacl-js)

[blue-crypt](https://git.rootprojects.org/root/acme.js)

[node-forge](https://github.com/digitalbazaar/forge)

## Prior Issues

- [ ] [Node-Forge](https://github.com/digitalbazaar/forge/issues/532)
- [ ] [PKI.js](https://github.com/PeculiarVentures/PKI.js/pull/230)
