package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"fmt"
	"github.com/vibros68/hdwallet/mnemonic"
	"golang.org/x/crypto/pbkdf2"
	"math/big"
)

const passphrase = "passphrase"
const secret = "a random secret key"

func main() {
	b := big.NewInt(64)
	b.Add(big.NewInt(4353455646456456454), big.NewInt(8353455646456456454))
	key := make([]byte, 32)
	rand.Read(key)
	fmt.Println(len(key), key)
	sentence,err := mnemonic.NewMnemonic(key)
	fmt.Println(sentence,err)
	k,err := mnemonic.MnemonicToEntropy(sentence)
	fmt.Println(key, k)
	seed := pbkdf2.Key([]byte(sentence),[]byte("mnemonic" + passphrase), 2048, 64, sha512.New)
	fmt.Println("seed: ", seed)
	// create Master Extended Keys
	h := hmac.New(sha512.New, []byte(secret))
	h.Write(seed)
	masterExtendedKey := h.Sum(nil)
	fmt.Println("masterExtendedKey: ", masterExtendedKey)
	fmt.Println("master private key: ", masterExtendedKey[:32])
	fmt.Println("master chain code: ", masterExtendedKey[32:])
	fmt.Println(len(masterExtendedKey[:32]))
}
