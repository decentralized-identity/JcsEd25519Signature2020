package proof;

import canonical.Canonical;
import net.i2p.crypto.eddsa.EdDSAPrivateKey;
import net.i2p.crypto.eddsa.spec.EdDSAPrivateKeySpec;
import net.i2p.crypto.eddsa.spec.EdDSAPublicKeySpec;
import org.junit.Assert;
import org.junit.Test;

import static proof.Proof.ED_SPEC;
import static proof.Proof.JCS_SIGNATURE_TYPE;

class GenericProvable
        implements Provable {
    final String data;
    Proof proof;

    public GenericProvable(final String data) {
        this.data = data;
    }

    @Override public Proof getProof() {
        return this.proof;
    }

    @Override public void setProof(Proof proof) {
        this.proof = proof;
    }

    @Override public String toJson() {
        return Canonical.toJson(this);
    }
}

public class ProofTest {
    final String keySeed = "12345678901234567890123456789012";
    final EdDSAPrivateKeySpec privKeySpec = new EdDSAPrivateKeySpec(keySeed.getBytes(), ED_SPEC);
    final EdDSAPrivateKey privKey = new EdDSAPrivateKey(privKeySpec);
    final EdDSAPublicKeySpec pubKeySpec = new EdDSAPublicKeySpec(privKey.getAbyte(), ED_SPEC);

    final String nonce = "0948bb75-60c2-4a92-ad50-01ccee169ae0";
    final String verificationMethod = "did:work:6sYe1y3zXhmyrBkgHgAgaq#key-1";

    final String testJSON = "{\"some\":\"one\",\"test\":\"two\",\"structure\":\"three\"}";

    @Test public void proofTest() {
        Provable provable = new GenericProvable(testJSON);
        Proof proof = null;
        try {
            proof = Proof.createEd25519Proof(provable, privKeySpec, verificationMethod, nonce);
        }
        catch (Exception e) {
            Assert.fail(e.getMessage());
        }
        provable.setProof(proof);

        Assert.assertEquals(nonce, proof.getNonce());
        Assert.assertEquals(verificationMethod, proof.getVerificationMethod());
        Assert.assertEquals(JCS_SIGNATURE_TYPE, proof.getType());

        try {
            Assert.assertTrue(Proof.verifyEd25519Proof(provable, pubKeySpec));
        }
        catch (Exception e) {
            Assert.fail(e.getMessage());
        }
    }
}
