package bls

import "fmt"

// SignatureBytes is the length of a BLS signature
const SignatureBytes = 48

// SecretKeyBytes is the length of a BLS private key
const SecretKeyBytes = 32

// PublicKeyBytes is the length of a BLS public key
const PublicKeyBytes = 96

// DigestBytes is the length of a BLS message hash/digest
//const DigestBytes = 96

// CompressedSignature is a compressed affine
type CompressedSignature [SignatureBytes]byte

// CompressedSecret is a compressed affine representing a SecretKey
type CompressedSecret [SecretKeyBytes]byte

// CompressedPublic is a compressed affine representing a PublicKey
type CompressedPublic [PublicKeyBytes]byte

// Message is a byte slice
type Message []byte

// Digest is a compressed affine
//type Digest [DigestBytes]byte

type SecretKey interface {
	// Sign returns the BLS signature of the giving message.
	Sign(m Message) Signature
	// PubKey returns the corresponding public key.
	PubKey() (PublicKey, error)
	// Compress compresses the secret key to a byte slice.
	Compress() CompressedSecret
}

type PublicKey interface {
	// Verify verifies a signature against a message and the public key.
	Verify(m Message, sig Signature) error
	// Aggregate adds an other public key to the current.
	Aggregate(other PublicKey) error
	// Compress compresses the public key to a byte slice.
	Compress() CompressedPublic
}

type Signature interface {
	// Aggregate adds an other signature to the current.
	//Aggregate(other Signature) error
	// Compress compresses the signature to a byte slice.
	Compress() CompressedSignature
}

type BlsManager interface {
	// GenerateKey generates a fresh key-pair for BLS signatures.
	GenerateKey() (SecretKey, PublicKey)
	//Aggregate aggregates signatures together into a new signature.
	Aggregate([]Signature) (Signature, error)
	//AggregatePublic aggregates public keys together into a new PublicKey.
	AggregatePublic([]PublicKey) (PublicKey, error)
	// VerifyAggregatedOne verifies each public key against a message.
	VerifyAggregatedOne([]PublicKey, Message, Signature) error
	// VerifyAggregatedN verifies each public key against each message.
	VerifyAggregatedN([]PublicKey, []Message, Signature) error
	//DecompressPublicKey
	DecompressPublicKey(CompressedPublic) (PublicKey, error)
	//DecompressPrivateKey
	DecompressPrivateKey(CompressedSecret) (SecretKey, error)
	//Decompress Signature
	DecompressSignature(CompressedSignature) (Signature, error)
}

func (b CompressedPublic) String() string {
	return fmt.Sprintf("%0x", b[:])
}

func (b CompressedSecret) String() string {
	return fmt.Sprintf("%0x", b[:])
}

func (b CompressedSignature) String() string {
	return fmt.Sprintf("%0x", b[:])
}
