package proof

import (
	"encoding/json"
	"github.com/mr-tron/base58"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/ed25519"
)

type GenericProvable struct {
	Data  map[string]interface{}
	Proof Proof `json:"proof"`
}

func (gp *GenericProvable) GetProof() *Proof {
	return &gp.Proof
}

func (gp *GenericProvable) SetProof(p Proof) {
	gp.Proof = p
}

var (
	keySeed       = []byte("12345678901234567890123456789012")
	issuerPrivKey = ed25519.NewKeyFromSeed(keySeed) // this matches the public key in didDocJson
	issuerPubKey  = issuerPrivKey.Public().(ed25519.PublicKey)

	nonce      = "0948bb75-60c2-4a92-ad50-01ccee169ae0"
	creatorKey = "did:work:6sYe1y3zXhmyrBkgHgAgaq#key-1"

	testJSON      = `{"some":"one","test":"two","structure":"three"}`
	differentJSON = `{"some":"one","test":"two","structure":"banana"}`
)

func TestGenericSign(t *testing.T) {
	sampleInput := `{"foo": "bar"}`
	var data map[string]interface{}
	err := json.Unmarshal([]byte(sampleInput), &data)
	assert.NoError(t, err)

	provable := GenericProvable{Data: data, Proof: Proof{
		Type: JCSSignatureType,
	}}

	signedDocBytes, err := GenericSign(&provable, issuerPrivKey)
	assert.NoError(t, err)

	var signedDoc GenericProvable
	assert.NoError(t, json.Unmarshal(signedDocBytes, &signedDoc))
	assert.NoError(t, VerifyEd25519Proof(&signedDoc, issuerPubKey))
}

func TestProofGeneration(t *testing.T) {
	var data map[string]interface{}
	err := json.Unmarshal([]byte(testJSON), &data)
	assert.NoError(t, err)

	provable := GenericProvable{Data: data}

	proofUnderTest, err := CreateEd25519Proof(&provable, issuerPrivKey, creatorKey, nonce)
	assert.NoError(t, err)
	assert.Equal(t, proofUnderTest.Nonce, nonce)
	assert.Equal(t, proofUnderTest.VerificationMethod, creatorKey)

	provable.Proof = *proofUnderTest
	assert.NoError(t, VerifyEd25519Proof(&provable, issuerPubKey))
}

func TestValidationOfProof(t *testing.T) {
	var data map[string]interface{}
	err := json.Unmarshal([]byte(testJSON), &data)
	assert.NoError(t, err)

	provable := GenericProvable{Data: data}

	proofUnderTest, err := CreateEd25519Proof(&provable, issuerPrivKey, creatorKey, nonce)
	assert.NoError(t, err)

	provable.Proof = *proofUnderTest
	assert.NoError(t, VerifyEd25519Proof(&provable, issuerPubKey))
	assert.NoError(t, err)

	var differentData map[string]interface{}
	assert.NoError(t, json.Unmarshal([]byte(differentJSON), &differentData))
	differentProvable := GenericProvable{Data: differentData}

	assert.Error(t, VerifyEd25519Proof(&differentProvable, issuerPubKey))
}

// Test vectors

type TestVector1 struct {
	Foo   string `json:"foo"`
	Proof `json:"proof"`
}

func (t *TestVector1) GetProof() *Proof {
	return &t.Proof
}

func (t *TestVector1) SetProof(p Proof) {
	t.Proof = p
}

type TestVector2 struct {
	ID             string       `json:"id"`
	PublicKey      []KeyDef     `json:"publicKey"`
	Authentication []string     `json:"authentication"`
	Service        []ServiceDef `json:"service"`
	Proof          `json:"proof"`
}

type KeyDef struct {
	ID              string `json:"id"`
	Type            string `json:"type"`
	Controller      string `json:"controller,omitempty"`
	PublicKeyBase58 string `json:"publicKeyBase58"`
}

type ServiceDef struct {
	ID              string `json:"id"`
	Type            string `json:"type"`
	ServiceEndpoint string `json:"serviceEndpoint"`
}

func (t *TestVector2) GetProof() *Proof {
	return &t.Proof
}

func (t *TestVector2) SetProof(p Proof) {
	t.Proof = p
}

func TestVectorsTest(t *testing.T) {
	privKey := "z3nisqMdwW7nZdWomCfUyRaezHzKEBfwRbvaMcJAqaMSbmjxuRfS5qz4ff3QAf1A5sZT4ZMcxYoGjN4K1VsDV7b"
	pubKey := "4CcKDtU1JNGi8U4D8Rv9CHzfmF7xzaxEAPFA54eQjRHF"

	privKeyBytes, err := base58.Decode(privKey)
	assert.NoError(t, err)

	pubKeyBytes, err := base58.Decode(pubKey)
	assert.NoError(t, err)

	t.Run("Test Vector 1", func(t *testing.T) {
		input := `{"foo":"bar","proof":{"type":"JcsEd25519Signature2020"}}`
		provable := TestVector1{
			Foo:   "bar",
			Proof: Proof{Type: JCSSignatureType},
		}
		expectedInputBytes, err := json.Marshal(provable)
		assert.Equal(t, string(expectedInputBytes), input)

		proofUnderTest, err := CreateEd25519ProofOptions(&provable, privKeyBytes, ProofOptions{
			Created: false,
		})
		assert.NoError(t, err)

		provable.Proof = *proofUnderTest
		assert.NoError(t, VerifyEd25519Proof(&provable, pubKeyBytes))

		output := `{"foo":"bar","proof":{"signatureValue":"4VCNeCSC4Daru6g7oij3QxUL2CS9FZkCYWRMUKyiLuPPK7GWFrM4YtYYQbmgyUXgGuxyKY5Wn1Mh4mmaRkbah4i4","type":"JcsEd25519Signature2020"}}`

		var provableOut GenericProvable
		err = json.Unmarshal([]byte(output), &provableOut)
		assert.NoError(t, err)
		assert.Equal(t, provableOut.Proof.SignatureValue, provable.Proof.SignatureValue)
	})

	t.Run("Test 2", func(t *testing.T) {
		input := `{"id":"did:example:abcd","publicKey":[{"id":"did:example:abcd#key-1","type":"JcsEd25519Signature2020","controller":"foo-issuer","publicKeyBase58":"not-a-real-pub-key"}],"authentication":null,"service":[{"id":"schema-id","type":"schema","serviceEndpoint":"service-endpoint"}],"proof":{"type":"JcsEd25519Signature2020"}}`
		provable := TestVector2{
			ID:             "did:example:abcd",
			PublicKey:      []KeyDef{
				{
					ID:              "did:example:abcd#key-1",
					Type:            "JcsEd25519Signature2020",
					Controller:      "foo-issuer",
					PublicKeyBase58: "not-a-real-pub-key",
				},
			},
			Authentication: nil,
			Service:        []ServiceDef{
				{
					ID:              "schema-id",
					Type:            "schema",
					ServiceEndpoint: "service-endpoint",
				},
			},
			Proof:          Proof{Type: JCSSignatureType},
		}
		expectedInputBytes, err := json.Marshal(provable)
		assert.Equal(t, string(expectedInputBytes), input)

		assert.NoError(t, err)

		proofUnderTest, err := CreateEd25519ProofOptions(&provable, privKeyBytes, ProofOptions{
			Created:            false,
			VerificationMethod: "",
			Nonce:              "",
		})
		assert.NoError(t, err)

		provable.Proof = *proofUnderTest
		assert.NoError(t, VerifyEd25519Proof(&provable, pubKeyBytes))
		assert.NoError(t, err)

		output := `{"id":"did:example:abcd","publicKey":[{"id":"did:example:abcd#key-1","type":"JcsEd25519Signature2020","controller":"foo-issuer","publicKeyBase58":"not-a-real-pub-key"}],"authentication":null,"service":[{"id":"schema-id","type":"schema","serviceEndpoint":"service-endpoint"}],"proof":{"signatureValue":"4qtzqwFxFYUifwfpPhxR6AABn94KnzWF768jcmjHHH8JYtUb4kAXxG6PttmJAbn3b6q1dfraXFdnUc1z2EGHqWdt","type":"JcsEd25519Signature2020"}}`

		var provableOut GenericProvable
		err = json.Unmarshal([]byte(output), &provableOut)
		assert.NoError(t, err)
		assert.Equal(t, provableOut.Proof.SignatureValue, provable.Proof.SignatureValue)
	})
}
