package proof

import (
	"crypto"
	cryptorand "crypto/rand"
	"fmt"
	"github.com/stretchr/testify/require"
	"signaturesuite/canonical"
	"time"

	"github.com/mr-tron/base58"
	"github.com/pkg/errors"
	"golang.org/x/crypto/ed25519"
)

const (
	JCSVerificationType = "JCSJsonWebVerificationKey2020"
	JCSSignatureType    = "JCSJsonWebSignature2020"
)

type Provable interface {
	GetProof() *Proof
	SetProof(p Proof)
}

// Proof a signed proof of a given ledger document
type Proof struct {
	Created        string `json:"created"`
	Creator        string `json:"creator"`
	Nonce          string `json:"nonce"`
	SignatureValue string `json:"signatureValue"`
	Type           string `json:"type"`
}

func CreateEd25519Proof(provable Provable, privKey ed25519.PrivateKey, fullyQualifiedKeyRef, nonce string) (*Proof, error) {
	currProof := provable.GetProof()
	if currProof != nil && currProof.SignatureValue != "" {
		return nil, errors.New("signature value on proof already set")
	}

	// create and set unsigned proof value
	proof := Proof{
		Created: time.Now().UTC().Format(time.RFC3339),
		Creator: fullyQualifiedKeyRef,
		Nonce:   nonce,
		Type:    JCSSignatureType,
	}
	provable.SetProof(proof)

	toSign, err := canonical.Marshal(provable)
	if err != nil {
		return nil, err
	}
	signature, err := privKey.Sign(cryptorand.Reader, toSign, crypto.Hash(0))
	if err != nil {
		return nil, errors.New("failed to sign JSON doc")
	}

	proof.SignatureValue = base58.Encode(signature)
	return &proof, nil
}

func VerifyEd25519Proof(provable Provable, pubKey ed25519.PublicKey) error {
	proof := provable.GetProof()
	emptyProof := Proof{}
	if proof == nil || *proof == emptyProof {
		return errors.New("empty proof")
	}
	if proof.Type != JCSSignatureType {
		return errors.Errorf("cannot verify proof with type %s as Ed25519 signature", proof.Type)
	}

	sigBytes, err := base58.Decode(proof.SignatureValue)
	if err != nil {
		return err
	}

	// Remove signature value from proof to validate
	provable.SetProof(Proof{
		Created:        proof.Created,
		Creator:        proof.Creator,
		Nonce:          proof.Nonce,
		Type:           proof.Type,
	})

	toSign, err := canonical.Marshal(provable)
	if err != nil {
		return err
	}
	vvv := string(toSign)
	require.NotEmpty(nil, vvv)

	if valid := ed25519.Verify(pubKey, toSign, sigBytes); !valid {
		return fmt.Errorf("failure while verifying signature (b58) %s for pub key (b58) %s", proof.SignatureValue, base58.Encode(pubKey))
	}
	return nil
}
