package proof;

import canonical.Canonical;
import net.i2p.crypto.eddsa.EdDSAEngine;
import net.i2p.crypto.eddsa.EdDSAPrivateKey;
import net.i2p.crypto.eddsa.EdDSAPublicKey;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;
import net.i2p.crypto.eddsa.spec.EdDSAParameterSpec;
import net.i2p.crypto.eddsa.spec.EdDSAPrivateKeySpec;
import net.i2p.crypto.eddsa.spec.EdDSAPublicKeySpec;
import org.bitcoinj.core.Base58;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.text.SimpleDateFormat;
import java.util.Date;

public final class Proof {

    public static final String JCS_VERIFICATION_TYPE = "JCSJsonWebVerificationKey2020";
    public static final String JCS_SIGNATURE_TYPE = "JCSJsonWebSignature2020";
    public static final EdDSAParameterSpec ED_SPEC = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519);

    private final String created;
    private final String verificationMethod;
    private final String nonce;
    private String signatureValue;
    private final String type;

    public Proof(final String created,
                 final String verificationMethod,
                 final String nonce,
                 final String signatureValue,
                 final String type) {
        this.created = created;
        this.verificationMethod = verificationMethod;
        this.nonce = nonce;
        this.signatureValue = signatureValue;
        this.type = type;
    }

    public static Proof createEd25519Proof(final Provable provable,
                                           final EdDSAPrivateKeySpec privKey,
                                           final String keyRef,
                                           final String nonce)
            throws InvalidKeyException, SignatureException, IOException, NoSuchAlgorithmException {

        final Signature sgr = new EdDSAEngine(MessageDigest.getInstance(ED_SPEC.getHashAlgorithm()));
        final PrivateKey sKey = new EdDSAPrivateKey(privKey);
        sgr.initSign(sKey);

        Proof proof = provable.getProof();
        if (proof != null && !proof.signatureValue.equals("")) {
            throw new SignatureException("Proof already contains signature.");
        }

        // create and set unsigned proof value
        proof = new Proof(Proof.getRFC3339Time(), keyRef, nonce, "", JCS_SIGNATURE_TYPE);
        provable.setProof(proof);

        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        final String canonicalDoc = Canonical.canonicalize(provable.toJson());
        final byte[] canonicalBytes = canonicalDoc.getBytes();
        baos.write(canonicalBytes);
        final byte[] toSign = baos.toByteArray();
        baos.close();

        // do the signing
        sgr.update(toSign);
        final byte[] signature = sgr.sign();

        // base58 encode signature
        final String base58Signature = Base58.encode(signature);

        proof.setSignatureValue(base58Signature);
        return proof;
    }

    public static boolean verifyEd25519Proof(final Provable provable, final EdDSAPublicKeySpec pubKey)
            throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, IOException {
        Proof proof = provable.getProof();
        if (proof.isEmpty()) {
            return false;
        }
        if (!proof.type.equals(JCS_SIGNATURE_TYPE)) {
            // we only know how to handle our own type
            return false;
        }

        // Decode signature
        final byte[] signature = Base58.decode(proof.signatureValue);
        final Signature sig = new EdDSAEngine(MessageDigest.getInstance(ED_SPEC.getHashAlgorithm()));

        // Remove signature and set proof to validate
        provable.setProof(new Proof(proof.created, proof.verificationMethod, proof.nonce, "", proof.type));
        final String canonicalDoc = Canonical.canonicalize(provable.toJson());
        final byte[] toVerify = canonicalDoc.getBytes();

        final PublicKey verificationKey = new EdDSAPublicKey(pubKey);
        sig.initVerify(verificationKey);
        sig.update(toVerify);
        return sig.verify(signature);
    }

    private static String getRFC3339Time() {
        return new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssXXX").format(new Date());
    }

    public String getCreated() {
        return created;
    }

    public String getVerificationMethod() {
        return verificationMethod;
    }

    public String getNonce() {
        return nonce;
    }

    public String getSignatureValue() {
        return signatureValue;
    }

    public void setSignatureValue(String signatureValue) {
        this.signatureValue = signatureValue;
    }

    public String getType() {
        return type;
    }

    @Override public String toString() {
        return Canonical.toJson(this);
    }

    public boolean isEmpty() {
        return this.created.equals("") && this.verificationMethod.equals("") && this.nonce.equals("")
                && this.signatureValue.equals("") && this.type.equals("");
    }
}
