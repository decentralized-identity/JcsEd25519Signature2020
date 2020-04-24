
const nacl = require('tweetnacl')
const bs58 = require('bs58')

// Leave this here... this is how the verificationMethod was created.
// let key = nacl.sign.keyPair()
// key = {
//     publicKey: Buffer.from(key.publicKey).toString('hex'),
//     secretKey: Buffer.from(key.secretKey).toString('hex'),
// }
// const key = {
//     publicKey: '53015daa95f69cbd3f431ff5a3b2eefe2bb5d9ea0d296607446aab7b7106f3ed',
//     secretKey: '8e2ef45a52a27af96b80d77c4019f04c47ca68e8a66fcac1fccf52d18124185c53015daa95f69cbd3f431ff5a3b2eefe2bb5d9ea0d296607446aab7b7106f3ed'
// }
// console.log(bs58.encode(Buffer.from(key.secretKey, 'hex')))

const verificationMethod = {
    "id": "did:example:123#key-1",
    "type": "JcsKey2020",
    publicKeyBase58: '6b23ioXQSAayuw13PGFMCAKqjgqoLTpeXWCy5WRfw28c',
    privateKeyBase58: '3qsrFcQqVuPpuGrRkU4wkQRvw1tc1C5EmEDPioS1GzQ2pLoThy5TYS2BsrwuzHYDnVqcYhMSpDhTXGst6H5ttFkG'
}

describe('ed25519', ()=>{
    it('can sign and verify', ()=>{
        const publicKey = bs58.decode(verificationMethod.publicKeyBase58)
        const secretKey = bs58.decode(verificationMethod.privateKeyBase58)
        const message = Buffer.from('hello');
        const signature = nacl.sign(message, new Uint8Array(secretKey))
        const expectedSignature = '0ccbeb905006a327b5112c7bfaa2a5918784209818a83750548b9965661b9d1d467c4078faacbaa36c1bd0f88673039adea51f5d216cd45cbf0e1528fb67f10a68656c6c6f';
        expect(Buffer.from(signature).toString('hex')).toBe(expectedSignature)
        const verifiedMessage = nacl.sign.open(new Uint8Array(Buffer.from(expectedSignature, 'hex')), new Uint8Array(publicKey))
        const expectedVerifiedMessage = 'hello' 
        expect(Buffer.from(verifiedMessage).toString()).toBe(expectedVerifiedMessage);
    })
})