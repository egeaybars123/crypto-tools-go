package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"fmt"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
)

// Mempool size: 64 (Hash bytes) + (Signature bytes)
func main() {
	hash := HashKeccak("avalanche")
	//fmt.Println(hash)

	privKey, _ := GeneratePrivKey()
	pubKey := privKey.PublicKey

	sig, err := SignDigest(privKey, hash)
	if err != nil {
		fmt.Println(err)
	}
	//fmt.Println(sig)
	fmt.Println(len(sig))

	sigNoRec := removeRecovery(sig)

	verified := ValidateSig(hash, sigNoRec, &pubKey)
	fmt.Println(verified)
	//publicKeyBytes := crypto.FromECDSAPub(publicKeyECDSA)
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
