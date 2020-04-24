const key = {
    publicKey: new Uint8Array(Buffer.from('53015daa95f69cbd3f431ff5a3b2eefe2bb5d9ea0d296607446aab7b7106f3ed', 'hex')),
    secretKey: new Uint8Array(Buffer.from('8e2ef45a52a27af96b80d77c4019f04c47ca68e8a66fcac1fccf52d18124185c53015daa95f69cbd3f431ff5a3b2eefe2bb5d9ea0d296607446aab7b7106f3ed', 'hex'))
}

const JCSJsonWebSignature2020 = require('./lib');

const document = {
    foo: 'bar',
    proof: {
        type: 'JCSJsonWebSignature2020',
    }
}

describe('JCSJsonWebSignature2020', ()=>{
    it('can sign and verify', ()=>{
        const signed = JCSJsonWebSignature2020.sign(document, key.secretKey)
        // console.log(JSON.stringify(signed, null, 2))
        expect(signed.proof.signatureValue).toBe('LgLRyP8ooEKM8vatGKqRfRV6hftanfVtzwn6k1ZUZZuSFYXNUX2a999mecezGHg8suvGGWxdnY4C2dDRAbSKn9AhvyxhPSKHjPmp2zPiLtCnnv8Bx67Fi1jhm76HFkfyv3FYPZy9eSTZw47e9BKojhYqH49tDMwJVZNC');
        const verified = JCSJsonWebSignature2020.verify(signed, key.publicKey)
        expect(verified).toBe(true);
    })

    it('fails when key is mutated', ()=>{
        const signed = JCSJsonWebSignature2020.sign(document, key.secretKey)
        const verified = JCSJsonWebSignature2020.verify(signed, new Uint8Array(Buffer.from('00015daa95f69cbd3f431ff5a3b2eefe2bb5d9ea0d296607446aab7b7106f3ed', 'hex')))
        expect(verified).toBe(false);
    })

    it('fails when signature is mutated', ()=>{
        const signed = JCSJsonWebSignature2020.sign(document, key.secretKey)
        signed.proof.signatureValue = signed.proof.signatureValue + '0'
        const verified = JCSJsonWebSignature2020.verify(signed, key.publicKey)
        expect(verified).toBe(false);
    })
})