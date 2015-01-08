package modules

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

var KeyError = errors.New("key error")

// 生成公私钥
// 返回 私钥，公钥，错误
func GenRsaKey(bits int) ([]byte, []byte, error) {
	// 生成私钥文件
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, err
	}
	derStream := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: derStream,
	}

	// 生成公钥文件
	publicKey := &privateKey.PublicKey
	derPkix, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, nil, err
	}
	publicKeyBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: derPkix,
	}

	return pem.EncodeToMemory(privateKeyBlock), pem.EncodeToMemory(publicKeyBlock), nil
}

// 加密
func RsaEncrypt(key, data []byte) ([]byte, error) {
	block, _ := pem.Decode(key)
	if block == nil {
		return nil, KeyError
	}
	keyInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	rsaKey := keyInterface.(*rsa.PublicKey)
	return rsa.EncryptPKCS1v15(rand.Reader, rsaKey, data)
}

// 解密
func RsaDecrypt(key, data []byte) ([]byte, error) {
	block, _ := pem.Decode(key)
	if block == nil {
		return nil, KeyError
	}
	rsaKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return rsa.DecryptPKCS1v15(rand.Reader, rsaKey, data)
}
