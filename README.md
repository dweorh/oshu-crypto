# oshu-crypto

It is a simple library for cryptography developed as a part of the [Oshu-gun](https://www.oshu-gun.com) project.

Its purpose was to standardize the node and the browser interface and make all keys exchangeable without any extra work. Also, to make encryption of text or base64 encoded strings easy.

But its purpose is not to be extremely configurable or flexible. For it, you can use another project like Sodium.

oshu-crypto provides symmetrical encryption AES-GCM 256 and asymmetrical encryption RSA-OAEP 4096-bit key.

It uses native implementations depending on the context.

[NodeJS Crypto](https://nodejs.org/api/crypto.html)

[Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Crypto)

## How to install it?

```bash
npm install @dweorh/oshu-crypto
```

## How to use it?

Check the examples folder.
Example01 is about symmetrical encryption.
Example02 is about asymmetrical encryption.
