package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"

	"github.com/Bluek404/messager/modules"

	"golang.org/x/crypto/sha3"
)

const (
	// 配置文件名称
	configFile = "messager.dat"
)

var (
	// 用于加密配置文件的密码
	password string = "Bluek404"
	// 服务器地址
	serverHost string = "127.0.0.1"
	// 服务器公钥
	serverPublicKey string = ""

	// 公钥
	publicKey []byte
	// 私钥
	privateKey []byte
)

func main() {
	_, err := os.Stat(configFile)
	if err != nil {
		if strings.Contains(fmt.Sprint(err), "no such file or directory") {
			log.Println("配置文件不存在")

			privateKey, publicKey, err = modules.GenRsaKey(2048)
			if err != nil {
				log.Fatal(err)
			}
			if privateKey == nil || publicKey == nil {
				log.Fatal("key error")
			}

			cfg := &config{
				ID:         "Bluek404",
				PrivateKey: privateKey,
				PublicKey:  publicKey,
			}

			data, err := modules.Encode(cfg)
			if err != nil {
				log.Fatal(err)
			}

			// 加密配置文件
			data, err = modules.AesEncrypt(data, sha3Sum256([]byte(password)))
			// 写入文件并设置只有当前用户拥有读写权限
			ioutil.WriteFile(configFile, data, 0600)
		} else {
			log.Fatal(err)
		}
	}

	data, err := ioutil.ReadFile(configFile)
	if err != nil {
		log.Fatal(err)
	}

	// 解密
	data, err = modules.AesDecrypt(data, sha3Sum256([]byte(password)))
	if err != nil {
		log.Fatal(err)
	}

	var cfg config
	err = modules.Decode(data, &cfg)
	if err != nil {
		log.Fatal(err)
	}
	log.Println(cfg)
}

// 返回32位hash
func sha3Sum256(data []byte) []byte { return sha3.New256().Sum(data)[len(data):] }

type config struct {
	ID         string
	PrivateKey []byte
	PublicKey  []byte
}
