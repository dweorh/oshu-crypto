import { OshuCrypto } from './crypto_common.js'

class OshuCryptoBrowser extends OshuCrypto {
    str2ab (str, input = 'base64') {
        str = input === 'base64' ? str : btoa(str)
        return Uint8Array.from(atob(str), c => c.charCodeAt(0))
    }
    
    ab2str (buf, input = 'base64') {
        let output = buf instanceof ArrayBuffer 
            ? String.fromCharCode.apply(null, new Uint8Array(buf))
            : String.fromCharCode.apply(null, buf)
        return input === 'base64' ? btoa(output) : output
    }
}

class OshuCryptoSymmetricalBrowser extends OshuCryptoBrowser {
    iv = false
    constructor(crypto) {
        super (crypto)
    }

    async generateKey () {
        let key = await this.crypto.subtle.generateKey(
            {
                name: "AES-GCM",
                length: 256, //can be  128, 192, or 256
            },
            true, //whether the key is extractable (i.e. can be used in exportKey)
            ["encrypt", "decrypt"]
        )
        return this.ab2str(await this.crypto.subtle.exportKey("raw", key))
    }

    async importKey (key, extractable = false) {
        this.key = await this.crypto.subtle.importKey(
            "raw",
            typeof key === 'string' ? this.str2ab(key) : key,
            { name: 'AES-GCM' },
            false,
            ["encrypt", "decrypt"]
        )
        return this.key
    }

    generateIv () {
        return this.ab2str(this.crypto.getRandomValues(new Uint8Array(12)))
    }

    importIv (iv) {
        this.iv = typeof iv === 'string' ? this.str2ab(iv) : iv
    }

    async encrypt (message, input = 'base64', output = 'base64') {
        if (!this.key || !this.iv) {
            throw new Error('Key or iv is missing!')
        }
        let crypto = await this.crypto.subtle.encrypt({
                name: "AES-GCM",
                iv: this.iv,
                //Additional authentication data (optional)
                // additionalData: ArrayBuffer,
                tagLength: 128, //can be 32, 64, 96, 104, 112, 120 or 128 (default)
            },
            this.key, //from generateKey or importKey
            this.str2ab(message, input) //ArrayBuffer of data you want to encrypt
        )

        return { message: output ? this.ab2str(crypto, output) : crypto, authTag: false }
    }

    async decrypt (message, authTag = false, output = 'base64', input = 'base64') {
        if (!this.key || !this.iv) {
            throw new Error('Key or iv is missing!')
        }
        let data = this.str2ab(message, input) //ArrayBuffer of the data
        if (authTag) {
            authTag = this.str2ab(authTag)
            let bytesData = new Uint8Array(data);
            let bytesAuthTag = new Uint8Array(authTag);
            let _data = new ArrayBuffer(bytesData.byteLength + bytesAuthTag.byteLength)
            let outputBytes = new Uint8Array(_data)

            for (let i = 0; i < bytesData.length; i++)
                outputBytes[i] = bytesData[i]

            for (let i = 0; i < bytesAuthTag.length; i++)
                outputBytes[bytesData.length + i] = bytesAuthTag[i]

            data = _data
        }
        let crypto = await this.crypto.subtle.decrypt(
            {
                name: "AES-GCM",
                iv: this.iv, //The initialization vector you used to encrypt
                // additionalData: ArrayBuffer, //The addtionalData you used to encrypt (if any)
                tagLength: 128, //The tagLength you used to encrypt (if any)
            },
            this.key, //from generateKey or importKey above
            data
        )
        return output ? this.ab2str(crypto, output) : crypto
    }
}

class OshuCryptoAsymmetricalBrowser extends OshuCryptoBrowser {
    pemHeaderPrivate = "-----BEGIN ENCRYPTED PRIVATE KEY-----\n"
    pemFooterPrivate = "\n-----END ENCRYPTED PRIVATE KEY-----"
    pemHeaderPublic = "-----BEGIN PUBLIC KEY-----\n"
    pemFooterPublic = "\n-----END PUBLIC KEY-----"
    constructor(crypto) {
        super (crypto)
    }

    async generateKey (passphrase = false) {
        let keys = await this.crypto.subtle.generateKey({
                name: "RSA-OAEP",
                modulusLength: 4096, // Consider using a 4096-bit key for systems that require long-term security
                publicExponent: new Uint8Array([1, 0, 1]),
                hash: "SHA-256",
                passphrase
            },
            true,
            ["encrypt", "decrypt"]
        )
        let publicKey = await this.crypto.subtle.exportKey("spki", keys.publicKey)
        let privateKey = await this.crypto.subtle.exportKey("pkcs8", keys.privateKey)
            
        return {
            publicKey: this.pemHeaderPublic + this.ab2str(publicKey) +  this.pemFooterPublic,
            privateKey: this.pemHeaderPrivate +  this.ab2str(privateKey) + this.pemFooterPrivate
        }
    }
    
    async importKey (key, passphrase = false) {
        if (this._isKeyPublic(key)){
            this.key = await this.crypto.subtle.importKey(
                "spki",
                this.str2ab(this._clearPEM(key)),
                { 
                    name: 'RSA-OAEP',
                    hash: "SHA-256",
                },
                false,
                ["encrypt"]
            )
        } else {
            this.key = await this.crypto.subtle.importKey(
                "pkcs8",
                this.str2ab(this._clearPEM(key)),
                { 
                    name: 'RSA-OAEP',
                    hash: "SHA-256",
                    passphrase: passphrase
                },
                false,
                ["decrypt"]
            )
        }
        return this.key
    }

    _isKeyPublic(key) {
        return key.indexOf(this.pemHeaderPublic) === 0
    }
    
    _clearPEM(key) {
        if (key.indexOf(this.pemHeaderPrivate) >= 0) {
            return key.substring(this.pemHeaderPrivate.length, key.indexOf(this.pemFooterPrivate))
        } else if (key.indexOf(this.pemHeaderPublic) >= 0) {
            return key.substring(this.pemHeaderPublic.length, key.indexOf(this.pemFooterPublic))
        }
        return key
    }
    
    async encrypt (message, input = 'base64', output = 'base64') {
        if (!this.key) {
            throw new Error('Key is missing!')
        }
        let crypto = await this.crypto.subtle.encrypt({
                name: "RSA-OAEP"
            },
            this.key,
            this.str2ab(message, input)
        );
        return output ? this.ab2str(crypto, output) : crypto
    }

    async decrypt (message, output = 'base64', input = 'base64') {
        if (!this.key) {
            throw new Error('Key is missing!')
        }
        let crypto = await this.crypto.subtle.decrypt(
            {
              name: "RSA-OAEP"
            },
            this.key,
            this.str2ab(message, input)
        );
        return output ? this.ab2str(crypto, output) : crypto
    }
}


export {
    OshuCryptoBrowser,
    OshuCryptoSymmetricalBrowser,
    OshuCryptoAsymmetricalBrowser
}