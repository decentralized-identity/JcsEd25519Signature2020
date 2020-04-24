package did

import (
	"github.com/google/uuid"
	"github.com/mr-tron/base58"
	"golang.org/x/crypto/ed25519"

	"signaturesuite/proof"
)

type UnsignedDIDDoc struct {
	ID             string       `json:"id"`
	PublicKey      []KeyDef     `json:"publicKey"`
	Authentication []string     `json:"authentication"`
	Service        []ServiceDef `json:"service"`
}

// DIDDoc a W3C compliant signed DID Document
type DIDDoc struct {
	*UnsignedDIDDoc
	*proof.Proof `json:"proof"`
}

func (d *DIDDoc) GetProof() *proof.Proof {
	return d.Proof
}

func (d *DIDDoc) SetProof(p proof.Proof) {
	d.Proof = &p
}

// KeyDef represents a DID public key
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

const (
	// InitialKey the key reference assigned to the first key in a DidDoc
	InitialKey      = "key-1"
	IssuerDIDMethod = "did:work:"
)

// GenerateDID generate a DID
func GenerateDID(publicKey *ed25519.PublicKey) string {
	bytes := *publicKey
	return IssuerDIDMethod + base58.Encode(bytes[0:16])
}

func SignDIDDoc(unsignedDoc UnsignedDIDDoc, privKey ed25519.PrivateKey, keyRef string) (*DIDDoc, error) {
	doc := DIDDoc{
		UnsignedDIDDoc: &unsignedDoc,
		Proof:          nil,
	}
	nonce := uuid.New().String()
	docProof, err := proof.CreateEd25519Proof(&doc, privKey, keyRef, nonce)
	doc.Proof = docProof
	return &doc, err
}

func ValidateDIDDocProof(didDoc DIDDoc, pubKey ed25519.PublicKey) error {
	return proof.VerifyEd25519Proof(&didDoc, pubKey)
}
