package proof

import (
	"crypto"
	cryptorand "crypto/rand"
	"encoding/json"
	"fmt"
	"signaturesuite/canonical"
	"time"

	"github.com/mr-tron/base58"
	"github.com/pkg/errors"
	"golang.org/x/crypto/ed25519"
)

const (
	JCSVerificationType = "JcsEd25519Key2020"
	JCSSignatureType    = "JcsEd25519Signature2020"
)

type Provable interface {
	GetProof() *Proof
	SetProof(p Proof)
}

// Proof a signed proof of a given ledger document
type Proof struct {
	Created            string `json:"created,omitempty"`
	VerificationMethod string `json:"verificationMethod,omitempty"`
	Nonce              string `json:"nonce,omitempty"`
	SignatureValue     string `json:"signatureValue,omitempty"`
	Type               string `json:"type,omitempty"`
}

type ProofOptions struct {
	Created            bool
	VerificationMethod string
	Nonce              string
}

func CreateEd25519ProofOptions(provable Provable, privKey ed25519.PrivateKey, opts ProofOptions) (*Proof, error) {
	currProof := provable.GetProof()
	if currProof != nil && currProof.SignatureValue != "" {
		return nil, errors.New("signature value on proof already set")
	}

	var created string
	if opts.Created {
		created = time.Now().UTC().Format(time.RFC3339)
	}
	// create and set unsigned proof value
	proof := Proof{
		Created:            created,
		VerificationMethod: opts.VerificationMethod,
		Nonce:              opts.Nonce,
		Type:               JCSSignatureType,
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

func CreateEd25519Proof(provable Provable, privKey ed25519.PrivateKey, fullyQualifiedKeyRef, nonce string) (*Proof, error) {
	currProof := provable.GetProof()
	if currProof != nil && currProof.SignatureValue != "" {
		return nil, errors.New("signature value on proof already set")
	}

	// create and set unsigned proof value
	proof := Proof{
		Created:            time.Now().UTC().Format(time.RFC3339),
		VerificationMethod: fullyQualifiedKeyRef,
		Nonce:              nonce,
		Type:               JCSSignatureType,
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
	var proofCopy Proof
	if err := deepCopy(provable.GetProof(), &proofCopy); err != nil {
		return err
	}
	emptyProof := Proof{}
	if proof == nil || *proof == emptyProof {
		return errors.New("empty proof")
	}
	if proof.Type != JCSSignatureType {
		return errors.Errorf("cannot verify proof with type %s as Ed25519 signature", proof.Type)
	}

	sigBytes, err := base58.Decode(proofCopy.SignatureValue)
	if err != nil {
		return err
	}

	// Remove signature value from proof to validate
	provable.SetProof(Proof{
		Created:            proof.Created,
		VerificationMethod: proof.VerificationMethod,
		Nonce:              proof.Nonce,
		Type:               proof.Type,
	})

	// Put the proof back
	defer func() { provable.SetProof(proofCopy) }()

	toSign, err := canonical.Marshal(provable)
	if err != nil {
		return err
	}

	if valid := ed25519.Verify(pubKey, toSign, sigBytes); !valid {
		return fmt.Errorf("failure while verifying signature (b58) %s for pub key (b58) %s", proof.SignatureValue, base58.Encode(pubKey))
	}
	return nil
}

func GenericSign(provable Provable, privKey ed25519.PrivateKey) ([]byte, error) {
	currProof := provable.GetProof()
	if currProof != nil && currProof.SignatureValue != "" {
		return nil, errors.New("signature value on proof already set")
	}

	// create and set unsigned proof value
	proof := Proof{
		Type: JCSSignatureType,
	}

	toSign, err := canonical.Marshal(provable)
	if err != nil {
		return nil, err
	}
	signature, err := privKey.Sign(cryptorand.Reader, toSign, crypto.Hash(0))
	if err != nil {
		return nil, errors.New("failed to sign doc")
	}

	proof.SignatureValue = base58.Encode(signature)
	provable.SetProof(proof)

	return json.Marshal(provable)
}

func deepCopy(from interface{}, to interface{}) error {
	bytes, err := json.Marshal(from)
	if err != nil {
		return err
	}
	return json.Unmarshal(bytes, to)
}
