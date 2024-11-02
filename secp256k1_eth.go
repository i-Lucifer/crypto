package crypto

import (
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"log"
	"math/big"
	"strings"

	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	secp_ecdsa "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"

	"golang.org/x/crypto/sha3"
)

const EthPrefix = "\x19Ethereum Signed Message:\n"

const PrivateKeyLen = 64
const PublicKeyLen = 65 // 04 + X + Y
const SignatureLen = 65 // R + S + V

func GetEthMessageHash(message string) (msgHash []byte) {
	msg := EthPrefix + fmt.Sprintf("%d", len(message)) + message
	return GetKeccak256Hash([]byte(msg))
}

func GetKeccak256Hash(msg []byte) (msgHash []byte) {
	hash := sha3.NewLegacyKeccak256()
	hash.Write([]byte(msg))
	return hash.Sum(nil)
}

func GetPrivateKeyWithEcdsa(privateKey string) (prikey *ecdsa.PrivateKey, err error) {
	lenth := len(privateKey)
	if lenth != PrivateKeyLen && lenth != PrivateKeyLen+2 {
		err = fmt.Errorf("invalid private key")
		return
	}
	if lenth == 66 {
		if privateKey[0] != '0' || privateKey[1] != 'x' {
			err = fmt.Errorf("invalid private key")
			return
		}
		privateKey = privateKey[2:]
	}

	pribKey, err := hex.DecodeString(privateKey)
	if err != nil {
		err = fmt.Errorf("invalid private key")
		return
	}

	bs256 := secp.S256()

	prikey = new(ecdsa.PrivateKey)
	prikey.PublicKey.Curve = bs256
	prikey.D = big.NewInt(0).SetBytes(pribKey)

	// https://en.bitcoin.it/wiki/Secp256k1
	// must less N(fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141)
	if prikey.D.Cmp(bs256.Params().N) >= 0 {
		err = fmt.Errorf("invalid private key")
		return
	}

	// must greater 0
	if prikey.D.Sign() <= 0 {
		err = fmt.Errorf("invalid private key")
		return
	}

	prikey.PublicKey.X, prikey.PublicKey.Y = bs256.ScalarBaseMult(pribKey)
	if prikey.PublicKey.X == nil || prikey.PublicKey.Y == nil {
		err = fmt.Errorf("invalid private key")
		return
	}
	return
}

type Bytes []byte

func (b Bytes) EncodeToString() string {
	return hex.EncodeToString(b)
}

func GetBytesPublicKeyByPrivateKey(publicKeyECDSA *ecdsa.PublicKey) (publicKey Bytes) {
	x := publicKeyECDSA.X.Bytes()
	y := publicKeyECDSA.Y.Bytes()

	// compressed G = 02 + x or 03 + x
	// uncompressed G = 04 + x + y
	publicKey = append(publicKey, 04)
	publicKey = append(publicKey, x...)
	publicKey = append(publicKey, y...)
	return
}

func GetEcdsaPublicKeyByPrivateKey(prikey *ecdsa.PrivateKey) (publicKeyECDSA *ecdsa.PublicKey, err error) {
	if prikey == nil {
		err = fmt.Errorf("invalid private key")
	}
	public := prikey.Public()
	publicKeyECDSA, ok := public.(*ecdsa.PublicKey)
	if !ok {
		err = fmt.Errorf("assert failed")
		return
	}
	if publicKeyECDSA == nil {
		err = fmt.Errorf("invalid public key")
		return
	}
	if publicKeyECDSA.X == nil || publicKeyECDSA.Y == nil {
		err = fmt.Errorf("invalid public key")
		return
	}
	return

}

func GetPublicKeyByPrivateKey(prikey *ecdsa.PrivateKey) (publicKey Bytes, err error) {
	if prikey == nil {
		err = fmt.Errorf("invalid private key")
	}
	public := prikey.Public()
	publicKeyECDSA, ok := public.(*ecdsa.PublicKey)
	if !ok {
		err = fmt.Errorf("assert failed")
		return
	}
	if publicKeyECDSA == nil {
		err = fmt.Errorf("invalid public key")
		return
	}
	if publicKeyECDSA.X == nil || publicKeyECDSA.Y == nil {
		err = fmt.Errorf("invalid public key")
		return
	}

	x := publicKeyECDSA.X.Bytes()
	y := publicKeyECDSA.Y.Bytes()
	publicKey = append(publicKey, 04)
	publicKey = append(publicKey, x...)
	publicKey = append(publicKey, y...)
	return

}

func GetEthAddressByBytePublicKey(publicKey []byte) (address string, err error) {
	lenth := len(publicKey)

	// check
	if lenth != PublicKeyLen {
		err = fmt.Errorf("invalid public key")
		return
	}
	if publicKey[0] != 4 {
		err = fmt.Errorf("invalid public key")
		return
	}

	XY := publicKey[1:]
	pubKeyHash := GetKeccak256Hash(XY)
	if len(pubKeyHash) != 32 {
		err = fmt.Errorf("invalid public key")
		return
	}
	pubKeyHash = pubKeyHash[12:]
	address = "0x" + hex.EncodeToString(pubKeyHash)
	return
}

func GetPublicKeyBySign(msgHash, signature []byte) (sigPublicKey []byte, err error) {
	if len(signature) != SignatureLen {
		log.Fatal("invalid signature 1")
		return
	}
	// R S V -> V R S

	sig := signature[64] + 27
	var sigs Bytes
	sigs = append(sigs, sig)
	sigs = append(sigs, signature[0:64]...)

	publicKey, _, err := secp_ecdsa.RecoverCompact(sigs, msgHash)
	if err != nil {
		log.Fatal("invalid signature 2")
	}

	sigPublicKey = publicKey.SerializeUncompressed()
	return
}

func ValidateSignature(message, signature, address string) (valid bool) {
	msgHash := GetEthMessageHash(message)
	if signature[0] == '0' && signature[1] == 'x' {
		signature = signature[2:]
	}
	sig, err := hex.DecodeString(signature)
	if err != nil {
		return
	}
	publicKeyBySign, err := GetPublicKeyBySign(msgHash, sig)
	if err != nil {
		return
	}
	addr, err := GetEthAddressByBytePublicKey(publicKeyBySign)
	if err != nil {
		return
	}
	return strings.ToLower(addr) == strings.ToLower(address)
}
