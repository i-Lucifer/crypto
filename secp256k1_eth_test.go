package crypto

import (
	"encoding/hex"
	"testing"
)

const message = "hello"
const privateKey = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func TestGetEthMessageHash(t *testing.T) {
	msgHash := GetEthMessageHash(message)
	t.Log(hex.EncodeToString(msgHash))
	// 50b2c43fd39106bafbba0da34fc430e1f91e3c96ea2acee2bc34119f92b37750
}

func TestGetAddressBySign(t *testing.T) {
	msgHash := GetEthMessageHash(message)
	sign := "182dc2e4432e152adb9c8a8837474986469144160b09f77a45645b6d9240ceb0368de7f12b5c522171ea4139c8dfa030c868710d39eedb0172e69a88904174d400"
	signature, err := hex.DecodeString(sign)
	if err != nil {
		t.Fatal(err)
	}
	publicKeyBySign, err := GetPublicKeyBySign(msgHash, signature)
	if err != nil {
		t.Fatal(err)
	}
	address, err := GetEthAddressByBytePublicKey(publicKeyBySign)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(address)
	// 0x8fd379246834eac74B8419FfdA202CF8051F7A03
}

func TestGetAddressByPriKey(t *testing.T) {
	priKey, err := GetPrivateKeyWithEcdsa(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	publicKeyByPri, _ := GetPublicKeyByPrivateKey(priKey)

	address, err := GetEthAddressByBytePublicKey(publicKeyByPri)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(address)
	// 0x8fd379246834eac74B8419FfdA202CF8051F7A03
}

func TestGetPublicKeyByPriKey(t *testing.T) {
	priKey, err := GetPrivateKeyWithEcdsa(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	publicKeyByPri, _ := GetPublicKeyByPrivateKey(priKey)

	// X:47953413657569298045469572009142904437504322226959437408902026114336204275379
	// Y:24748197810672996843207408197061820032795023151205007187553471688928477483430

	t.Logf("\n %s \n", publicKeyByPri.EncodeToString())
	// 046a04ab98d9e4774ad806e302dddeb63bea16b5cb5f223ee77478e861bb583eb336b6fbcb60b5b3d4f1551ac45e5ffc4936466e7d98f6c7c0ec736539f74691a6
}

func TestValidateSignature(t *testing.T) {
	sign := "0x182dc2e4432e152adb9c8a8837474986469144160b09f77a45645b6d9240ceb0368de7f12b5c522171ea4139c8dfa030c868710d39eedb0172e69a88904174d400"
	address := "0x8fd379246834eac74B8419FfdA202CF8051F7A03"
	valid := ValidateSignature(message, sign, address)
	if !valid {
		t.Fatal("invalid signature")
	}
}
