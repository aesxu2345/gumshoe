/*
 * Licensed under the Apache License, Version 2.0 (the License);
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an AS IS BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package cd59

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"time"
	"unicode"
)

// 证书生成配置（封装为结构体）
type CertificateConfig struct {
	Subject      string
	NotBefore    time.Time
	NotAfter     time.Time
	SerialNumber *big.Int
	SignatureAlg x509.SignatureAlgorithm
}

// 证书生成器（封装核心逻辑）
type CertificateGenerator struct {
	config    CertificateConfig
	privKey   crypto.Signer
	publicKey crypto.PublicKey
}

// 兼容旧函数的工厂方法
func NewLegacyGenerator(subject, privKeyPEM, pubKeyPEM string) (*CertificateGenerator, error) {
	// 参数校验
	if err := validateCommonName(subject); err != nil {
		return nil, fmt.Errorf("subject校验失败: %w", err)
	}

	// 解析密钥
	privKey, err := parsePrivateKey(privKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("私钥解析失败: %w", err)
	}

	pubKey, err := parsePublicKey(pubKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("公钥解析失败: %w", err)
	}

	// 验证密钥对
	if !PublicKeysEqual(privKey.Public(), pubKey) {
		return nil, errors.New("公钥与私钥不匹配")
	}

	// 自动选择签名算法
	sigAlg, err := detectSignatureAlgorithm(privKey)
	if err != nil {
		return nil, err
	}

	return &CertificateGenerator{
		config: CertificateConfig{
			Subject:      subject,
			NotBefore:    time.Date(1999, 6, 1, 0, 0, 0, 0, time.UTC),
			NotAfter:     time.Date(1999, 7, 1, 0, 0, 0, 0, time.UTC),
			SerialNumber: big.NewInt(time.Now().UnixNano()),
			SignatureAlg: sigAlg,
		},
		privKey:   privKey,
		publicKey: pubKey,
	}, nil
}

// 证书验证器（封装验证逻辑）
type CertificateVerifier struct {
	certPool *x509.CertPool
}

func NewVerifier() *CertificateVerifier {
	return &CertificateVerifier{
		certPool: x509.NewCertPool(),
	}
}

// 原入口函数的OOP封装
func (g *CertificateGenerator) Generate() (string, error) {
	template := &x509.Certificate{
		SerialNumber:       g.config.SerialNumber,
		Subject:            pkix.Name{CommonName: g.config.Subject},
		NotBefore:          g.config.NotBefore,
		NotAfter:           g.config.NotAfter,
		KeyUsage:           x509.KeyUsageDigitalSignature,
		ExtKeyUsage:        []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		SignatureAlgorithm: g.config.SignatureAlg,
	}

	derBytes, err := x509.CreateCertificate(
		rand.Reader,
		template,
		template,
		g.publicKey,
		g.privKey,
	)
	if err != nil {
		return "", fmt.Errorf("证书生成失败: %w", err)
	}

	return encodePEM("CERTIFICATE", derBytes), nil
}

// 原验证函数的OOP封装
func (v *CertificateVerifier) Verify(certPEM string) (string, string, bool, error) {
	cert, err := decodeCertificate(certPEM)
	if err != nil {
		return "", "", false, err
	}

	// 验证自签名
	if err := cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature); err != nil {
		return cert.Subject.CommonName, "", false, nil
	}

	// 编码公钥
	pubPEM, err := encodePublicKey(cert.PublicKey)
	if err != nil {
		return cert.Subject.CommonName, "", false, err
	}

	// 校验CommonName
	if err := validateCommonName(cert.Subject.CommonName); err != nil {
		return cert.Subject.CommonName, pubPEM, false, err
	}

	return cert.Subject.CommonName, pubPEM, true, nil
}

// 以下是保持兼容的原函数（调用OOP实现）------------------------------

// GenerateCertificateFromPEM 兼容入口函数
func GenerateCertificateFromPEM(subject string, privKeyPEM string, pubKeyPEM string) (string, error) {
	gen, err := NewLegacyGenerator(subject, privKeyPEM, pubKeyPEM)
	if err != nil {
		return "", err
	}
	return gen.Generate()
}

// VerifyAndExtractSubjectFromPEM 兼容入口函数
func VerifyAndExtractSubjectFromPEM(certPEM string) (string, string, bool, error) {
	verifier := NewVerifier()
	return verifier.Verify(certPEM)
}

// 辅助方法 ------------------------------------------------------
func detectSignatureAlgorithm(privKey crypto.Signer) (x509.SignatureAlgorithm, error) {
	switch k := privKey.(type) {
	case *rsa.PrivateKey:
		return x509.SHA256WithRSA, nil
	case *ecdsa.PrivateKey:
		return x509.ECDSAWithSHA256, nil
	case ed25519.PrivateKey:
		return x509.PureEd25519, nil
	default:
		return x509.UnknownSignatureAlgorithm, fmt.Errorf("不支持的私钥类型: %T", k)
	}
}

func encodePEM(blockType string, derBytes []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  blockType,
		Bytes: derBytes,
	}))
}

func decodeCertificate(certPEM string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil, errors.New("PEM解码失败")
	}
	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("无效的PEM类型: %s", block.Type)
	}
	return x509.ParseCertificate(block.Bytes)
}

func encodePublicKey(pubKey crypto.PublicKey) (string, error) {
	pubDER, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return "", err
	}
	return encodePEM("PUBLIC KEY", pubDER), nil
}

// 保持原有辅助函数不变...
func validateCommonName(cn string) error {
	if cn == "" {
		return errors.New("CommonName 不能为空")
	}
	if len(cn) > 64 {
		return fmt.Errorf("CommonName 长度超过 64 字节")
	}
	for _, r := range cn {
		if r > unicode.MaxASCII { // 非 ASCII 字符
			return fmt.Errorf("CommonName 包含非 ASCII 字符: %q", r)
		}
		if r < 32 || r > 126 { // 不可打印字符
			return fmt.Errorf("CommonName 包含不可打印的 ASCII 字符: %q", r)
		}
	}
	return nil
}
func parsePrivateKey(privKeyPEM string) (crypto.Signer, error) {
	block, _ := pem.Decode([]byte(privKeyPEM))
	if block == nil {
		return nil, errors.New("PEM解码失败")
	}

	var privKey crypto.Signer
	var err error

	switch block.Type {
	case "RSA PRIVATE KEY":
		privKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		privKey, err = x509.ParseECPrivateKey(block.Bytes)
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		switch k := key.(type) {
		case *rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey:
			privKey = k.(crypto.Signer)
		default:
			return nil, errors.New("不支持的PKCS#8密钥类型")
		}
	default:
		return nil, fmt.Errorf("不支持的私钥类型: %s", block.Type)
	}

	if err != nil {
		return nil, fmt.Errorf("私钥解析失败: %w", err)
	}
	return privKey, nil
}
func parsePublicKey(pubKeyPEM string) (crypto.PublicKey, error) {
	block, _ := pem.Decode([]byte(pubKeyPEM))
	if block == nil {
		return nil, errors.New("公钥PEM解码失败")
	}

	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("公钥解析失败: %w", err)
	}
	return pubKey, nil
}
func PublicKeysEqual(a, b interface{}) bool {
	// RSA公钥比对
	if aRSA, ok := a.(*rsa.PublicKey); ok {
		bRSA, ok := b.(*rsa.PublicKey)
		return ok &&
			aRSA.E == bRSA.E &&
			aRSA.N.Cmp(bRSA.N) == 0
	}

	// ECDSA公钥比对
	if aECDSA, ok := a.(*ecdsa.PublicKey); ok {
		bECDSA, ok := b.(*ecdsa.PublicKey)
		return ok &&
			aECDSA.Curve == bECDSA.Curve &&
			aECDSA.X.Cmp(bECDSA.X) == 0 &&
			aECDSA.Y.Cmp(bECDSA.Y) == 0
	}

	// Ed25519公钥比对
	if aEd, ok := a.(ed25519.PublicKey); ok {
		bEd, ok := b.(ed25519.PublicKey)
		return ok &&
			bytes.Equal(aEd, bEd)
	}

	// 未知类型
	return false
}
