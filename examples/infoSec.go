package main

import (
	"bufio"
	"bytes"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"flag"
	"fmt"
	"github.com/auyer/steganography"
	"image/png"
	"log"
	"os"
)

var inputPath, outputPath string

func init() {
	flag.StringVar(&inputPath, "i", "./examples/input.png", "Path to the the input image")
	flag.StringVar(&outputPath, "o", "./examples/output.png", "Path to the the output image")
}
func main() {
	fmt.Println("enter a text to encrypt into image")
	buff := bufio.NewReader(os.Stdin)
	data, _ := buff.ReadString('\n')
	data = data[:len(data)-1]
	destPrivate, _ := rsa.GenerateKey(rand.Reader, 1024)
	destPublicKey := destPrivate.PublicKey
	cipher, _ := rsa.EncryptPKCS1v15(rand.Reader, &destPublicKey, []byte(data))
	h := md5.New()
	h.Write(cipher)
	hashed := hex.EncodeToString(h.Sum(nil))
	cipherHash, _ := rsa.EncryptPKCS1v15(rand.Reader, &destPublicKey, []byte(hashed))
	cipher = append([]byte{byte(len(cipher))}, cipher...)
	cipher = append(cipher, cipherHash...)
	inFile, _ := os.Open(inputPath)
	reader := bufio.NewReader(inFile)
	img, _ := png.Decode(reader)
	w := new(bytes.Buffer)
	err := steganography.Encode(w, img, cipher)
	if err != nil {
		log.Printf("Error Encoding file %v", err)
		panic(err)
	}
	outFile, _ := os.Create(outputPath)
	w.WriteTo(outFile)
	outFile.Close()
	inFile, _ = os.Open(outputPath)
	defer inFile.Close()

	reader = bufio.NewReader(inFile)
	img, _ = png.Decode(reader)

	sizeOfMessage := steganography.GetMessageSizeFromImage(img)

	msg := steganography.Decode(sizeOfMessage, img)
	mainCipher := msg[1 : msg[0]+1]
	newData, _ := destPrivate.Decrypt(rand.Reader, mainCipher, nil)
	cipherNewHash := msg[msg[0]+1:]
	newHash, _ := destPrivate.Decrypt(rand.Reader, cipherNewHash, nil)
	h2 := md5.New()
	h2.Write(mainCipher)
	hashGenerated := hex.EncodeToString(h2.Sum(nil))
	//check hash
	if hashGenerated != string(newHash) {
		fmt.Println("invalid hash")
	}

	fmt.Println("after decrypt image data: ", string(newData))
}
