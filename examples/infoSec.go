package main

import (
	"bufio"
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"flag"
	"fmt"
	"github.com/auyer/steganography"
	"image/png"
	"log"
	"os"
	"strings"
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
	key := "123lksd#4flksjdf"
	cipher, _ := steganography.Encrypt(key, data)
	h := md5.New()
	h.Write([]byte(cipher))
	hashed := hex.EncodeToString(h.Sum(nil))
	cipher += hashed
	inFile, _ := os.Open(inputPath)
	reader := bufio.NewReader(inFile)
	img, _ := png.Decode(reader)
	w := new(bytes.Buffer)
	err := steganography.Encode(w, img, []byte(cipher))
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
	data, _ = steganography.Decrypt(key, strings.ReplaceAll(string(msg), hashed, ""))
	fmt.Println("after decrypt image data: ", data)
}
