const nacl = require('tweetnacl')
const canonicalize = require('canonicalize');
const bs58 = require('bs58')

const sign = (docJson, privateKeyUInt8Array) =>{
    const withoutSignature = {
        ...docJson
    }
    if (withoutSignature.proof){
        delete withoutSignature.proof.signatureValue;
    }
    const message = Buffer.from(canonicalize(withoutSignature));
    const signature = nacl.sign(message, privateKeyUInt8Array)
    const signatureValue = bs58.encode(Buffer.from(signature))
    withoutSignature.proof.signatureValue = signatureValue
    return withoutSignature;
}

const verify = (docJson, publicKeyUInt8Array) =>{
    let verifiedMessage;
    try{
        verifiedMessage = nacl.sign.open(new Uint8Array(bs58.decode(docJson.proof.signatureValue)), publicKeyUInt8Array)
        if (verifiedMessage === null){
            throw new Error('Signature verification failure.')
        }
    } catch(e){
        return false;
    }

    const withoutSignature = {
        ...docJson
    }
    delete withoutSignature.proof.signatureValue;
    const message = canonicalize(withoutSignature);
    if (Buffer.from(verifiedMessage).toString() !== message){
        throw new Error('Signature verification failed.')
    }
   return true
}

module.exports = {
    sign,
    verify
}