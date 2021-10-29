package steganography

import (
	"crypto/aes"
)

func Encrypt(key string, plainText string) (string, error) {
	plainData := []byte(plainText)
	toComplete := len(plainData) % 16
	for i := 0; i < 16-toComplete; i++ {
		plainData = append(plainData, 0)
	}
	var cypherText = make([]byte, len(plainData))
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}
	for i, j := 0, 16; i < len(plainData); i, j = i+16, j+16 {
		block.Encrypt(cypherText[i:j], plainData[i:j])
	}
	return string(cypherText), nil
}
func Decrypt(key string, cypherText string) (string, error) {
	cypherData := []byte(cypherText)
	var plainText = make([]byte, len(cypherData))
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}
	for i, j := 0, 16; i < len(cypherData); i, j = i+16, j+16 {
		block.Decrypt(plainText[i:j], cypherData[i:j])
	}
	return string(plainText), nil
}
