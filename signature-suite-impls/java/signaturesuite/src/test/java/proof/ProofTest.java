package proof;

import canonical.Canonical;
import com.google.gson.Gson;
import did.Did;
import did.KeyDef;
import did.ServiceDef;
import did.UnsignedDidDoc;
import net.i2p.crypto.eddsa.EdDSAPrivateKey;
import net.i2p.crypto.eddsa.spec.EdDSAPrivateKeySpec;
import net.i2p.crypto.eddsa.spec.EdDSAPublicKeySpec;
import org.bitcoinj.core.Base58;
import org.junit.Assert;
import org.junit.Test;

import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

import static proof.Proof.ED_SPEC;
import static proof.Proof.JCS_SIGNATURE_TYPE;

class GenericProvable implements Provable {
    final String data;
    Proof proof;

    public GenericProvable(final String data) {
        this.data = data;
    }

    @Override
    public Proof getProof() {
        return this.proof;
    }

    @Override
    public void setProof(Proof proof) {
        this.proof = proof;
    }

    @Override
    public String toJson() {
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

    @Test
    public void proofTest() {
        Provable provable = new GenericProvable(testJSON);
        Proof proof = null;
        try {
            proof = Proof.createEd25519Proof(provable, privKeySpec, verificationMethod, nonce);
        } catch (Exception e) {
            Assert.fail(e.getMessage());
        }
        provable.setProof(proof);

        Assert.assertEquals(nonce, proof.getNonce());
        Assert.assertEquals(verificationMethod, proof.getVerificationMethod());
        Assert.assertEquals(JCS_SIGNATURE_TYPE, proof.getType());

        try {
            Assert.assertTrue(Proof.verifyEd25519Proof(provable, pubKeySpec));
        } catch (Exception e) {
            Assert.fail(e.getMessage());
        }
    }

    class TV1 implements Provable {
        final String foo;
        Proof proof;

        public TV1(final String foo) {
            this.foo = foo;
        }

        @Override
        public Proof getProof() {
            return this.proof;
        }

        @Override
        public void setProof(Proof proof) {
            this.proof = proof;
        }

        @Override
        public String toJson() {
            return Canonical.toJson(this);
        }
    }

    @Test
    public void testVector1() {
        String input = "{\"foo\":\"bar\",\"proof\":{\"type\":\"JcsEd25519Signature2020\"}}";
        String knownPubKey = "4CcKDtU1JNGi8U4D8Rv9CHzfmF7xzaxEAPFA54eQjRHF";
        byte[] knownPubKeyBytes = Base58.decode(knownPubKey);

        // we are using the known key
        Assert.assertArrayEquals(privKey.getAbyte(), knownPubKeyBytes);

        Proof proof = null;
        try {
            proof = Proof.genericEd25519Signature(input, privKey, false, "", "");
        } catch (Exception e) {
            Assert.fail(e.getMessage());
        }

        Provable provable = new TV1("bar");
        provable.setProof(proof);

        try {
            Assert.assertTrue(Proof.verifyEd25519Proof(provable, pubKeySpec));
        } catch (Exception e) {
            Assert.fail(e.getMessage());
        }

        final String expectedSignature = "4VCNeCSC4Daru6g7oij3QxUL2CS9FZkCYWRMUKyiLuPPK7GWFrM4YtYYQbmgyUXgGuxyKY5Wn1Mh4mmaRkbah4i4";
        Assert.assertEquals(expectedSignature, proof.getSignatureValue());
    }

    class TV2 implements Provable {
        private final String id;
        private final KeyDef[] publicKey;
        private final String[] authentication;
        private final ServiceDef[] service;

        public TV2(final String id,
                   final KeyDef[] publicKey,
                   final String[] authentication,
                   final ServiceDef[] service) {
            this.id = id;
            this.publicKey = publicKey;
            this.authentication = authentication;
            this.service = service;
        }

        Proof proof;


        @Override
        public Proof getProof() {
            return this.proof;
        }

        @Override
        public void setProof(Proof proof) {
            this.proof = proof;
        }

        @Override
        public String toJson() {
            return Canonical.toJson(this);
        }
    }

    @Test
    public void testVector2() {
        String input = "{\"id\":\"did:example:abcd\",\"publicKey\":[{\"id\":\"did:example:abcd#key-1\",\"type\":\"JcsEd25519Signature2020\",\"controller\":\"foo-issuer\",\"publicKeyBase58\":\"not-a-real-pub-key\"}],\"authentication\":null,\"service\":[{\"id\":\"schema-id\",\"type\":\"schema\",\"serviceEndpoint\":\"service-endpoint\"}],\"proof\":{\"type\":\"JcsEd25519Signature2020\"}}";
        String knownPubKey = "4CcKDtU1JNGi8U4D8Rv9CHzfmF7xzaxEAPFA54eQjRHF";
        byte[] knownPubKeyBytes = Base58.decode(knownPubKey);

        // we are using the known key
        Assert.assertArrayEquals(privKey.getAbyte(), knownPubKeyBytes);

        Proof proof = null;
        try {
            proof = Proof.genericEd25519Signature(input, privKey, false, "", "");
        } catch (Exception e) {
            Assert.fail(e.getMessage());
        }

        final Provable provable = new TV2("did:example:abcd", new KeyDef[]{new KeyDef("did:example:abcd#key-1", "JcsEd25519Signature2020", "foo-issuer", "not-a-real-pub-key")}, null, new ServiceDef[]{new ServiceDef("schema-id", "schema", "service-endpoint")});
        provable.setProof(proof);

        try {
            Assert.assertTrue(Proof.verifyEd25519Proof(provable, pubKeySpec));
        } catch (Exception e) {
            Assert.fail(e.getMessage());
        }

        final String expectedSignature = "4qtzqwFxFYUifwfpPhxR6AABn94KnzWF768jcmjHHH8JYtUb4kAXxG6PttmJAbn3b6q1dfraXFdnUc1z2EGHqWdt";
        Assert.assertEquals(expectedSignature, proof.getSignatureValue());
    }
}