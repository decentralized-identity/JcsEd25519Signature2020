const bs58 = require('bs58')

const verificationMethod = {
    "id": "did:example:123#key-1",
    "type": "JcsKey2020",
    publicKeyBase58: '6b23ioXQSAayuw13PGFMCAKqjgqoLTpeXWCy5WRfw28c',
    privateKeyBase58: '3qsrFcQqVuPpuGrRkU4wkQRvw1tc1C5EmEDPioS1GzQ2pLoThy5TYS2BsrwuzHYDnVqcYhMSpDhTXGst6H5ttFkG'
}

const publicKey = bs58.decode(verificationMethod.publicKeyBase58)
const secretKey = bs58.decode(verificationMethod.privateKeyBase58)


const JcsEd25519Signature2020 = require('./lib');
const document = require('./document.json')


describe('JcsEd25519Signature2020', ()=>{
    it('can sign and verify', ()=>{
        const signed = JcsEd25519Signature2020.sign(document, secretKey)
        // console.log(JSON.stringify(signed, null, 2))
        expect(signed.proof.signatureValue).toBe("5TcawVLuoqRjCuu4jAmRqBcKoab1YVqxG8RXnQwvQBHNwP7RhPwXhzhTLVu3dKGposo2mmtfx9AwcqB2Mwnagup1JT5Yr9u3SjzLCc6kx4wW6HG5SKcra4SauhutN94s8Eo");
        const verified = JcsEd25519Signature2020.verify(signed, publicKey)
        expect(verified).toBe(true);
    })

    it('fails when key is mutated', ()=>{
        const signed = JcsEd25519Signature2020.sign(document, secretKey)
        const verified = JcsEd25519Signature2020.verify(signed, new Uint8Array(Buffer.from('00015daa95f69cbd3f431ff5a3b2eefe2bb5d9ea0d296607446aab7b7106f3ed', 'hex')))
        expect(verified).toBe(false);
    })

    it('fails when signature is mutated', ()=>{
        const signed = JcsEd25519Signature2020.sign(document, secretKey)
        signed.proof.signatureValue = signed.proof.signatureValue + '0'
        const verified = JcsEd25519Signature2020.verify(signed, publicKey)
        expect(verified).toBe(false);
    })
})