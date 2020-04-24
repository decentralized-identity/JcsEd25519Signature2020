
const nacl = require('tweetnacl')

// let key = nacl.sign.keyPair()
// key = {
//     publicKey: Buffer.from(key.publicKey).toString('hex'),
//     secretKey: Buffer.from(key.secretKey).toString('hex'),
// }
const key = {
publicKey: '53015daa95f69cbd3f431ff5a3b2eefe2bb5d9ea0d296607446aab7b7106f3ed',
secretKey: '8e2ef45a52a27af96b80d77c4019f04c47ca68e8a66fcac1fccf52d18124185c53015daa95f69cbd3f431ff5a3b2eefe2bb5d9ea0d296607446aab7b7106f3ed'
}


describe('ed25519', ()=>{
    it('can sign and verify', ()=>{
        const publicKey = Buffer.from(key.publicKey, 'hex')
        const secretKey = Buffer.from(key.secretKey, 'hex')
        const message = Buffer.from('hello');
        const signature = nacl.sign(message, new Uint8Array(secretKey))
        const expectedSignature = '0ccbeb905006a327b5112c7bfaa2a5918784209818a83750548b9965661b9d1d467c4078faacbaa36c1bd0f88673039adea51f5d216cd45cbf0e1528fb67f10a68656c6c6f';
        expect(Buffer.from(signature).toString('hex')).toBe(expectedSignature)
        const verifiedMessage = nacl.sign.open(new Uint8Array(Buffer.from(expectedSignature, 'hex')), new Uint8Array(publicKey))
        const expectedVerifiedMessage = 'hello' 
        expect(Buffer.from(verifiedMessage).toString()).toBe(expectedVerifiedMessage);
    })
})