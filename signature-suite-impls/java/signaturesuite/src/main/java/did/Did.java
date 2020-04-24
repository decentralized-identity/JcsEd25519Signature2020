package did;

import canonical.Canonical;
import net.i2p.crypto.eddsa.EdDSAPublicKey;
import net.i2p.crypto.eddsa.spec.EdDSAPrivateKeySpec;
import net.i2p.crypto.eddsa.spec.EdDSAPublicKeySpec;
import org.bitcoinj.core.Base58;
import proof.Proof;
import proof.Provable;

import java.util.Arrays;
import java.util.UUID;

public final class Did
        extends UnsignedDidDoc
        implements Provable {
    public static final String INITIAL_KEY = "key-1";
    public static final String DID_METHOD_PREFIX = "did:work:";

    private Proof proof;

    private Did(final UnsignedDidDoc unsignedDidDoc, final Proof proof) {
        super(unsignedDidDoc.getId(), unsignedDidDoc.getPublicKey(), unsignedDidDoc.getAuthentication(),
                unsignedDidDoc.getService());
        this.proof = proof;
    }

    public static String generateDID(final EdDSAPublicKey pubKey) {
        final byte[] pubKeyBytes = pubKey.getAbyte();
        final byte[] firstSixteen = Arrays.copyOfRange(pubKeyBytes, 0, 16);
        return DID_METHOD_PREFIX + Base58.encode(firstSixteen);
    }

    public static Did signDIDDoc(final UnsignedDidDoc unsignedDidDoc,
                                 final EdDSAPrivateKeySpec privKey,
                                 final String keyRef)
            throws Exception {
        final String nonce = UUID.randomUUID().toString();
        Did didDoc = new Did(unsignedDidDoc, null);
        final Proof proof = Proof.createEd25519Proof(didDoc, privKey, keyRef, nonce);
        didDoc.setProof(proof);
        return didDoc;
    }

    public static boolean validateDidDocProof(final Did didDoc, final EdDSAPublicKeySpec pubKey)
            throws Exception {
        return Proof.verifyEd25519Proof(didDoc, pubKey);
    }

    public UnsignedDidDoc getUnsignedDidDoc() {
        return new UnsignedDidDoc(this.getId(), this.getPublicKey(), this.getAuthentication(), this.getService());
    }

    public Proof getProof() {
        return proof;
    }

    @Override public void setProof(Proof proof) {
        this.proof = proof;
    }

    @Override public String toJson() {
        return Canonical.toJson(this);
    }

    @Override public String toString() {
        return Canonical.toJson(this);
    }
}

