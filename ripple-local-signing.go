package main

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"

	"github.com/shengdoushi/base58"
	"golang.org/x/crypto/ed25519"
)

var ED25519_SEED_PREFIX = [3]int{0x01, 0xE1, 0x4B}
var SEED = "sEdTxxiE6VhWghZ7FLRFvuR4V4etLwb"

// decodes seed using base58 checksum
// removes ed25519 prefix and checksum value from decoded value
func decode_seed(seed string) []byte {
	var cksum [4]byte
	decoded_seed, b58_err := base58.Decode(seed, base58.RippleAlphabet)
	if b58_err != nil {
		fmt.Println("Error on decoding seed:", b58_err)
		return nil
	}

	copy(cksum[:], decoded_seed[len(decoded_seed)-4:])

	if checksum(decoded_seed[:len(decoded_seed)-4]) != cksum {
		fmt.Println("Error on checksum:")
		return nil
	}

	payload := decoded_seed[len(ED25519_SEED_PREFIX) : len(decoded_seed)-4]

	return payload
}

// hashes using sha512 and gets first 32 byte
func sha512_half(b []byte) []byte {
	hasher := sha512.New()
	hasher.Write(b)
	return hasher.Sum(nil)[:32]
}

// hashes checksum for seed
func checksum(input []byte) (cksum [4]byte) {
	h := sha256.Sum256(input)
	h2 := sha256.Sum256(h[:])
	copy(cksum[:], h2[:4])
	return
}

// sign message locally
func sign_tx(unsigned_tx string, priv_key ed25519.PrivateKey) string {
	message, msg_err := hex.DecodeString(unsigned_tx)

	if msg_err != nil {
		fmt.Println(msg_err)
	}

	signed_messages := ed25519.Sign(priv_key, message)

	return hex.EncodeToString(signed_messages)
}

func main() {

	decoded := decode_seed(SEED)
	fmt.Println("Decoded", hex.EncodeToString(decoded))

	raw_private := sha512_half(decoded)
	fmt.Println("Raw Private:", hex.EncodeToString(raw_private))

	priv_key := ed25519.NewKeyFromSeed(raw_private)

	var unsigned_tx = "5354580012000022000000002401CD28A1201B000000646140000000000F424068400000000000000A7321ED4CD4D55E1275337DC7144EFF3C97A0CC7C57E857284C59F5751DB41CDB7D8ABD8114F2368C3E1D18FA779511A4B09A9BD2977BE4AD9283149030B59F8092B515612ED24D8806FB8E9DDA04E9"

	signed_tx := sign_tx(unsigned_tx, priv_key)

	fmt.Println("Signed msg:", signed_tx)
}
