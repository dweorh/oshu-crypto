import { OshuCrypto } from './crypto_common.js'
import { OshuCryptoAsymmetricalBrowser, OshuCryptoSymmetricalBrowser } from './crypto_browser.js'
import { OshuCryptoAsymmetricalNode, OshuCryptoSymmetricalNode } from './crypto_nodejs.js'
class OshuCryptoFactory {
    _crypto = false
    constructor () {
    }
    
    static async create (asymmetrical) {
        if (!OshuCryptoFactory._crypto) {
            OshuCryptoFactory._crypto = await OshuCryptoFactory.getCrypto()
        }

        return OshuCryptoFactory.nodejs() ? OshuCryptoFactory._createNode(asymmetrical) : OshuCryptoFactory._createBrowser(asymmetrical)
    }

    static async _createBrowser(asymmetrical) {
        return asymmetrical 
            ? new OshuCryptoAsymmetricalBrowser(OshuCryptoFactory._crypto)
            : new OshuCryptoSymmetricalBrowser(OshuCryptoFactory._crypto)
    }

    static async _createNode(asymmetrical) {
        return asymmetrical 
            ? new OshuCryptoAsymmetricalNode(OshuCryptoFactory._crypto)
            : new OshuCryptoSymmetricalNode(OshuCryptoFactory._crypto)
    }

    static async getCrypto () {
        if (OshuCryptoFactory.nodejs()) {
            const crypto = await import('crypto')
            return crypto
        } else {
            return window.crypto
        }
    }

    static nodejs () {
        return typeof window === 'undefined'
    }
}

export {
    OshuCrypto,
    OshuCryptoFactory
}