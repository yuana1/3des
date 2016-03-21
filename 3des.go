package main

import (
	"bytes"
	"crypto/cipher"
	"crypto/des"
	"flag"
	"fmt"
	"github.com/howeyc/gopass"
	"io/ioutil"
)

const KEY_SIZE int = 24

func PKCS5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func PKCS5Unpadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	if length-unpadding <= 0 {
		return make([]byte, 0)
	} else {
		return origData[:(length - unpadding)]
	}

}

func Encrypt3(key, src []byte) []byte {

	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		panic(err)
	}
	bs := block.BlockSize()
	src = PKCS5Padding(src, bs)
	blockMode := cipher.NewCBCEncrypter(block, key[:8])

	dst := make([]byte, len(src))

	blockMode.CryptBlocks(dst, src)
	return dst
}
func Decrypt3(key, src []byte) []byte {

	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		panic(err)
	}
	blockMode := cipher.NewCBCDecrypter(block, key[:8])
	dst := make([]byte, len(src))

	blockMode.CryptBlocks(dst, src)
	dst = PKCS5Unpadding(dst)
	return dst
}

func genKey3(key []byte) []byte {
	kkey := make([]byte, 0, KEY_SIZE)
	ede2Key := []byte(key)
	length := len(ede2Key)
	if length > KEY_SIZE {
		kkey = append(kkey, ede2Key[:KEY_SIZE]...)
	} else {
		div := KEY_SIZE / length
		mod := KEY_SIZE % length
		for i := 0; i < div; i++ {
			kkey = append(kkey, ede2Key...)
		}
		kkey = append(kkey, ede2Key[:mod]...)
	}
	return kkey
}

func main() {

	t := flag.String("t", "<en/de>", "-t <en/de> 选择操作类型，加密还是解密")

	file := flag.String("f", "filename", "-f <filename>")

	isGenDectyptFile := flag.Bool("df", false, "-df 是否生成解密")

	flag.Parse()

	if *t == "en" {

		for i := 0; i < 3; i++ {
			fmt.Print("请输入密钥： ")
			pwd1, _ := gopass.GetPasswdMasked()
			fmt.Print("请重复输入密钥： ")
			pwd2, _ := gopass.GetPasswdMasked()
			if !bytes.Equal(pwd1, pwd2) {
				fmt.Println("两次输入的密钥不匹配，请重新输入！")
			} else {
				key := genKey3(pwd1)
				info, _ := ioutil.ReadFile(*file)
				dst := Encrypt3(key, info)
				ioutil.WriteFile(*file+"_enctypted", dst, 0666)
				fmt.Println("已生成加密文件" + *file + "_enctypted，请妥善保管您的密钥！")
				break
			}
		}

	} else if *t == "de" {
		for i := 0; i < 3; i++ {
			fmt.Print("请输入密钥： ")
			pwd, _ := gopass.GetPasswdMasked() // Masked gopass.getPasswd
			key := genKey3(pwd)
			info, _ := ioutil.ReadFile(*file)
			src := Decrypt3(key, info)
			if len(src) == 0 {
				fmt.Println("密钥不对，请重新输入！")
			} else {
				fmt.Println(string(src))
				if *isGenDectyptFile {
					ioutil.WriteFile(*file+"_dectypted", src, 0666)
					fmt.Println("已生成解密文件" + *file + "_dectypted，请妥善保管！")
				}
				break
			}

		}

	}
}
