package proof

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/ed25519"
)

type GenericProvable struct {
	Data map[string]interface{}
	Proof Proof
}

func (g *GenericProvable) GetProof() *Proof {
	return &g.Proof
}

func (g *GenericProvable) SetProof(p Proof) {
	g.Proof = p
}

var (
	keySeed       = []byte("12345678901234567890123456789012")
	issuerPrivKey = ed25519.NewKeyFromSeed(keySeed) // this matches the public key in didDocJson
	issuerPubKey  = issuerPrivKey.Public().(ed25519.PublicKey)

	nonce             = "0948bb75-60c2-4a92-ad50-01ccee169ae0"
	creatorKey        = "did:work:6sYe1y3zXhmyrBkgHgAgaq#key-1"

	testJSON      = `{"some":"one","test":"two","structure":"three"}`
	differentJSON = `{"some":"one","test":"two","structure":"banana"}`
)

func TestProofGeneration(t *testing.T) {
	var data map[string]interface{}
	err := json.Unmarshal([]byte(testJSON), &data)
	assert.NoError(t, err)

	provable := GenericProvable{Data: data}

	proofUnderTest, err := CreateEd25519Proof(&provable, issuerPrivKey, creatorKey, nonce)
	assert.NoError(t, err)
	assert.Equal(t, proofUnderTest.Nonce, nonce)
	assert.Equal(t, proofUnderTest.Creator, creatorKey)

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