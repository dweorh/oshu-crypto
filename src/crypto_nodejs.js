import { OshuCrypto } from './crypto_common.js'
// import { Buffer } from 'buffer'
class OshuCryptoNode extends OshuCrypto {
    key = false
    enc_details = false

    str2ab (str, input = 'base64') {
        let buffer =  Buffer.from(str, input)
        let arrayBuffer = new ArrayBuffer(buffer.byteLength)
        let typedArray = new Uint8Array(arrayBuffer);
        for (var i = 0; i < buffer.length; ++i) {
            typedArray[i] = buffer[i];
        }
        return arrayBuffer
    }
    
    ab2str (buf, input = 'base64') {
        return Buffer.from(buf).toString(input)
    }
}

class OshuCryptoSymmetricalNode extends OshuCryptoNode {
    iv = false
    cipher = false
    decipher = false
    constructor(crypto) {
        super (crypto)
    }

    async init () {
        await this.generateKey()
        this.generateIv()
    }

    generateKey () {
        return this.ab2str(Buffer.from(this.crypto.randomBytes(32), 'utf8'));
    }

    generateIv () {
        return this.ab2str(Buffer.from(this.crypto.randomBytes(12), 'utf8'));
    }

    importKey (key) {
        this.key = typeof key === 'string' ? this.str2ab(key) : key
    }

    importIv (iv) {
        this.iv = typeof iv === 'string' ? this.str2ab(iv) : iv
    }

    encrypt (message, input = 'base64', output = 'base64') {
        if (!this.key || !this.iv) {
            throw new Error('Key or iv is missing!')
        }
        if (!this.cipher) {
            this._createCipher()
        }
        let enc = this.cipher.update(message, 'utf8', 'base64')
            enc += this.cipher.final('base64')

        return { message: enc, authTag: this.ab2str(this.cipher.getAuthTag()) }
    }

    decrypt (message, authTag, output = 'base64', input = 'base64') {
        if (!this.key || !this.iv) {
            throw new Error('Key or iv is missing!')
        }
        if (!this.decipher) {
            this._createDecipher()
        }

        if (typeof authTag === 'string') {
            authTag = this.str2ab(authTag)
        }
        if (authTag) {
            this.decipher.setAuthTag(authTag);
        } else  {
            let nonceCiphertextTag = Buffer.from(message, 'base64')
            message = nonceCiphertextTag.slice(0, -16)
            this.decipher.setAuthTag(nonceCiphertextTag.slice(-16))
        }
        let str = this.decipher.update(message, 'base64', 'utf8');
        str += this.decipher.final('utf8');
        return str;
    }

    _createCipher() {
        this.cipher = this.crypto.createCipheriv('aes-256-gcm', this.key, this.iv);
    }
    _createDecipher() {
        this.decipher = this.crypto.createDecipheriv('aes-256-gcm', this.key, this.iv);
    }
}

class OshuCryptoAsymmetricalNode extends OshuCryptoNode {
     constructor(crypto) {
        super (crypto)
    }

    async generateKey (passphrase = false) {
        return await new Promise((resolve, reject) => {
            this.crypto.generateKeyPair('rsa', {
                modulusLength: 4096,
                publicKeyEncoding: {
                  type: 'spki',
                  format: 'pem'
                },
                privateKeyEncoding: {
                  type: 'pkcs8',
                  format: 'pem',
                  cipher: 'aes-256-cbc',
                  passphrase: passphrase || 'oshu'
                }
              }, (err, publicKey, privateKey) => {
                if (err) {
                    reject(err)
                } else {
                    resolve({ privateKey, publicKey })
                }
              })
        })
    }

    async importKey (key, passphrase = false) {
        let enc_details = {
                padding: this.crypto.constants.RSA_PKCS1_OAEP_PADDING,
                oaepHash: "sha256",
            }
        if (passphrase) {
            enc_details.passphrase = passphrase
        }
        this.key = key
        // this.key = this._clearPEM(key)
        this.enc_details = enc_details
        return this.key
    }

    
    async encrypt (message, input = 'base64', output = 'base64') {
        if (!this.key) {
            throw new Error('Key is missing!')
        }
        let encrypted = this.crypto.publicEncrypt({
            key: this.key,
            ...this.enc_details
          },
          this.str2ab(message, input)
        )
        return output ? this.ab2str(encrypted, output) : encrypted
    }

    async decrypt (message, output = 'base64', input = 'base64') {
        if (!this.key) {
            throw new Error('Key is missing!')
        }

        let decrypted = this.crypto.privateDecrypt({
            key: this.key,
            ...this.enc_details
          },
          this.str2ab(message, input))
        return output ? this.ab2str(decrypted, output) : decrypted
    }
}

export {
    OshuCryptoNode,
    OshuCryptoAsymmetricalNode,
    OshuCryptoSymmetricalNode
}