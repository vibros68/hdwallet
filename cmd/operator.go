package main

import (
	"encoding/binary"
	"fmt"
	"math/big"
)

func main() {
	num := big.NewInt(2001)
	fmt.Println(binary.BigEndian.Uint16(num.Bytes()))
}