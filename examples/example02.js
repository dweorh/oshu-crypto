/* 
    Example 02

    This is an example how to use oshu-crypto for asymmetrical encryption on both ends, node and web browser.

    This scenario shows how to send encrypted message from node to a browser, which means crypto keys belongs to the web user.
*/

// Here I need to force import for a browser, because oshu-crypto detects context, and in this case will import crypto_nodejs.js only
import { OshuCryptoFactory } from "../src/index.js";
import { OshuCryptoAsymmetricalBrowser } from "../src/crypto_browser.js"

(async() => {
    // Dummy text for encryption, not too long because asymmetrical encryption is very limited
    let text = 'Here is some text'

    // Create a crypto object, context dependent
    let o = await OshuCryptoFactory.create(true)

    // Force to create node's browser implementation
    const crypto = await import('crypto')
    let web = new OshuCryptoAsymmetricalBrowser(crypto.webcrypto)

    // Generate web user's keys
    let key = await web.generateKey()

    // Import user's publicKey on the node's side
    await o.importKey(key.publicKey)

    // Encrypt text message, that's why it's ascii, not 'base64' which is default input type
    let enc = await o.encrypt(text, 'ascii')

    // Web user needs to import its private key to decode message    
    await web.importKey(key.privateKey)

    // Input type was an ascii, so here we provide the same input type
    let dec = await web.decrypt(enc, 'ascii')


    console.log({ enc, dec })
})()