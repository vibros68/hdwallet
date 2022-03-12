package mnemonic

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/big"
	"strings"
)

func init() {
	SetWords(English)
}

var (
	wordsMap  map[string]int
	wordsList []string
)

func SetWords(words []string) {
	wordsMap = map[string]int{}
	wordsList = words
	for k, word := range wordsList {
		wordsMap[word] = k
	}
}

var (
	InvalidEntropyLength = fmt.Errorf("the entropy length should be multiple of 32 bits and between 128 and 256 bits")
	InvalidMnemonicLength = fmt.Errorf("the number of words should be 12, 15, 18, 21 or 24")
	InvalidCheckSum = fmt.Errorf("invalid checksum")

)

var (
	bigTwo     = big.NewInt(2)
	bigOne     = big.NewInt(1)
	bit11Shift = big.NewInt(2048)
	bit11Max   = big.NewInt(2047)
)

var (
	checkSumMaskMap = map[int]*big.Int{
		12: big.NewInt(15),
		15: big.NewInt(31),
		18: big.NewInt(63),
		21: big.NewInt(127),
		24: big.NewInt(255),
	}
)

func NewMnemonic(entropy []byte) (string, error) {
	// validate entropy length, it should be multiple of 32 bits
	// and between 128 and 256 bits
	var entropyBitLen = len(entropy) * 8
	var validLength = entropyBitLen%32 == 0 && entropyBitLen >= 128 && entropyBitLen <= 256
	if !validLength {
		return "", InvalidEntropyLength
	}
	var checksumBitLength = entropyBitLen / 32
	var wordsLen = (entropyBitLen + checksumBitLength) / 11

	entropy = addCheckSum(entropy)
	var dataInt = big.NewInt(0).SetBytes(entropy)
	var word = big.NewInt(0)
	var words = make([]string, wordsLen)
	for i := wordsLen-1; i >= 0; i-- {
		word.And(dataInt, bit11Max)
		dataInt.Div(dataInt, bit11Shift)
		index := binary.BigEndian.Uint16(padByteSlice(word.Bytes(), 2))
		words[i] = wordsList[int(index)]
	}

	return strings.Join(words, " "), nil
}

// addCheckSum add a checksum for the entropy. it is created by hashing the entropy by SHA256
// and then take 1 bit of that hash for every 32 bits of entropy, and add it to the end of our entropy.
func addCheckSum(entropy []byte) []byte {
	var entropyInt = big.NewInt(0).SetBytes(entropy)
	var hash = sha256.Sum256(entropy)
	var firstChecksomeByte = hash[0]
	var bitAdded = len(entropy) / 4
	for i := 0; i < bitAdded; i++ {
		// shift 1 bit
		entropyInt.Mul(entropyInt, bigTwo)
		// Set rightmost bit if leftmost checksum bit is set
		if firstChecksomeByte&(1<<(7-i)) > 0 {
			entropyInt.Or(entropyInt, bigOne)
		}
	}

	return entropyInt.Bytes()
}

func MnemonicToEntropy(mnemonic string) ([]byte, error) {
	words, err := getWordsList(mnemonic)
	if err != nil {
		return nil, err
	}
	checkSumMask, ok := checkSumMaskMap[len(words)]
	if !ok {
		return nil, InvalidMnemonicLength
	}
	var dataInt = big.NewInt(0)
	var wordBytes [2]byte
	for _, w := range words {
		dataInt.Mul(dataInt, bit11Shift)
		wordIndex, ok := wordsMap[w]
		if !ok {
			return nil, fmt.Errorf("the word '%s' is not available on words pool", w)
		}
		binary.BigEndian.PutUint16(wordBytes[:], uint16(wordIndex))
		dataInt.Or(dataInt, big.NewInt(0).SetBytes(wordBytes[:]))
	}
	entropyWithCheckSum := dataInt.Bytes()

	dataInt.Div(dataInt, big.NewInt(0).And(checkSumMask, bigOne))

	entropy := dataInt.Bytes()

	if bytes.Compare(entropyWithCheckSum, addCheckSum(entropy)) == 0 {
		return entropy, nil
	}

	return nil, InvalidCheckSum
}

func getWordsList(mnemonic string) (wordsList []string, err error) {
	wordsList = strings.Fields(mnemonic)
	// Get num of words
	numOfWords := len(wordsList)

	// The number of words should be 12, 15, 18, 21 or 24
	if numOfWords%3 != 0 || numOfWords < 12 || numOfWords > 24 {
		return nil, InvalidMnemonicLength
	}
	return
}

// padByteSlice returns a byte slice of the given size with contents of the
// given slice left padded and any empty spaces filled with 0's.
func padByteSlice(slice []byte, length int) []byte {
	offset := length - len(slice)
	if offset <= 0 {
		return slice
	}

	newSlice := make([]byte, length)
	copy(newSlice[offset:], slice)

	return newSlice
}