package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"fmt"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
)

// Mempool size: 32 (Hash bytes) + 64 (Signature bytes) = 96 bytes
func main() {
	hash := HashKeccak("avalanche")
	//fmt.Println(hash)
	fmt.Println(len(hash))

	privKey, _ := GeneratePrivKey()
	pubKey := privKey.PublicKey

	sig, err := SignDigest(privKey, hash)
	if err != nil {
		fmt.Println(err)
	}
	//fmt.Println(sig)
	fmt.Println(len(sig))

	sigNoRec := removeRecovery(sig)
	fmt.Println(len(sigNoRec))

	joined := EncodeDataSig(hash, sigNoRec)
	fmt.Println(len(joined))

	newHash, newSig := DecodeDataSig(joined)
	fmt.Println(len(newHash))
	fmt.Println(len(newSig))

	verified := ValidateSig(hash, sigNoRec, &pubKey)
	fmt.Println(verified)
	//publicKeyBytes := crypto.FromECDSAPub(publicKeyECDSA)
}

func EncodeDataSig(hash []byte, sig []byte) []byte {
	return append(hash, sig...)
}

func DecodeDataSig(encoded []byte) ([]byte, []byte) {
	hash := encoded[:32]
	sig := encoded[32:96]

	return hash, sig
}

func HashKeccak(input string) []byte {
	test := []byte(input)
	hashed := crypto.Keccak256(test)
	return hashed
}

func removeRecovery(sig []byte) []byte {
	return sig[:len(sig)-1]
}

func ValidateSig(hash []byte, sig []byte, pubKey *ecdsa.PublicKey) bool {
	publicKeyBytes := crypto.FromECDSAPub(pubKey)
	//sigPublicKeyECDSA, err := crypto.SigToPub(hash, sig)
	/* if err != nil {
		log.Fatal(err)
	}
	sigPublicKeyBytes := crypto.FromECDSAPub(sigPublicKeyECDSA)
	matches := bytes.Equal(sigPublicKeyBytes, publicKeyBytes) */
	verified := crypto.VerifySignature(publicKeyBytes, hash, sig)

	return verified
}

func GeneratePrivKey() (*ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(secp256k1.S256(), rand.Reader)
	return key, err
}

func SignDigest(privKey *ecdsa.PrivateKey, hash []byte) ([]byte, error) {
	sig, err := crypto.Sign(hash[:], privKey)
	return sig, err
}
