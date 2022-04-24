/* 
    Example 01

    This is an example how to use oshu-crypto for symmetrical encryption on both ends, node and web browser.

    This scenario shows how to send encrypted message from node to a browser.
*/

// Here I need to force import for a browser, because oshu-crypto detects context, and in this case will import crypto_nodejs.js only
import {  OshuCryptoFactory } from "../src/index.js";
import { OshuCryptoSymmetricalBrowser } from "../src/crypto_browser.js"

(async() => {
    // Any text to encrypt
    let text = `Lorem ipsum dolor sit amet, consectetur adipiscing elit. Mauris et tristique tellus. Fusce ex quam, commodo sit amet sodales et, facilisis eu augue. In ut leo lacus. Nulla sit amet erat quis neque vestibulum semper. Mauris posuere vitae tortor eu rhoncus. Sed lorem orci, bibendum eu nulla at, feugiat hendrerit quam. Ut fringilla, mi eget tincidunt euismod, mauris lorem posuere ligula, sed ornare metus nibh sit amet ex.

    Maecenas ut enim vitae dui aliquet vulputate eu quis tellus. Vestibulum venenatis arcu vel mauris mattis, eget dignissim mauris facilisis. Sed mollis diam vitae metus aliquet malesuada. Sed eleifend elit eu tristique.`

    // Create a crypto object, context dependent
    let o = await OshuCryptoFactory.create(false)

    // Force to create node's browser implementation
    const crypto = await import('crypto')
    let web = new OshuCryptoSymmetricalBrowser(crypto.webcrypto)
   
    // Generate node's crypto keys
    let key = await o.generateKey()
    let iv = await o.generateIv()

    // Node and web users need to import node's key
    await web.importKey(key)
    await web.importIv(iv)
    o.importKey(key)
    o.importIv(iv)

    // Node can encrypt the text
    let enc = await o.encrypt(text)

    // Web user can decrypt it
    let dec = await web.decrypt(enc.message, enc.authTag, 'ascii')

    console.log({ text, enc, dec })
})()