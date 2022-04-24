class OshuCrypto {
    crypto = false
    key = false
    constructor (crypto) {
        this.crypto = crypto
    }
    async generateKey () { throw new Error('Not implemented') }
    async importKey () { throw new Error('Not implemented!') }
    async encrypt () { throw new Error('Not implemented!') }
    async decrypt () { throw new Error('Not implemented!') }
}

export {
    OshuCrypto
}