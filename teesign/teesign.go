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

package teesign

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"
)

/*func Veif(strpm string) bool {
// 新公钥PEM
pubPEM := []byte(`-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAx+ZapVwnOBwSbLd9kQx1
26kl5UO0xEHOYAMblnrDgXt4CMXMbxV7Rjk9lC144mi0XLibdPjExiLM3vh12T9c
0UbcJTwDUhEeezaQ05qjRbi6+mbRcBT+oZMx6kKTN5/h2Yp9jFnylLPWHc7rWNaV
OR/vhYeIah0jN1xAwIgJ0aqDtxlmY8ICYLg/vKVZ7eYfyiEcqz8l6mHiIt+5SsJG
Oz4RMee/ILE6NK81V/Zyf9aSaYLwagmr/8Wuvi+OgPcmzd4QaY9O0y0P6jMCicwa
P6GYBzUtMiDWn8xByqt076rxwfbkLLYxKp833i9IgkT3yM112AnwHn7yvshMmLgh
nwIDAQAB
-----END PUBLIC KEY-----`)
pubPEM := []byte(strpm)
// 生成指定域名的终端证书
targetCert := issueLeafCert(pubPEM, "global.opteesign.org")
saveCertToFile(targetCert, "target.crt")

// 验证证书
pubPEMResult, valid, err := VerifyCert("CA.cer", "target.crt")
fmt.Printf("证书验证结果:\n公钥: %s\n有效: %t\n错误: %v\n",
	pubPEMResult[:40]+"...", valid, err) // 简略显示
return valid
}
*/

// 签发证书函数（新增domain参数）
func issueLeafCert(pubPEM []byte, domain string) []byte {
	caCert, caKey := createCACert()
	saveCertToFile(caCert, "CA.cer")

	pubKey := parsePublicKey(pubPEM)
	parentCert, _ := x509.ParseCertificate(caCert)

	// 动态设置域名
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: domain}, // 使用传入域名
		DNSNames:     []string{domain},              // 设置SAN扩展
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(99, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, parentCert, pubKey, caKey)
	if err != nil {
		panic(err)
	}
	return derBytes
}

// 增强版公钥解析（支持多种格式）
func parsePublicKey(pubPEM []byte) interface{} {
	block, _ := pem.Decode(pubPEM)
	if block == nil {
		panic("无效的PEM格式")
	}

	// 尝试PKIX解析
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err == nil {
		return pub
	}

	// 尝试PKCS1解析
	if rsaPub, err := x509.ParsePKCS1PublicKey(block.Bytes); err == nil {
		return rsaPub
	}

	panic("无法识别的公钥格式")
}

// 其他函数保持不变（createCACert/VerifyCert/saveCertToFile等）
func createCACert() ([]byte, *rsa.PrivateKey) {
	privKey := parsePrivateKey()

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(2024),
		Subject:               pkix.Name{Organization: []string{"GlobalTEE"}, CommonName: "CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(100, 0, 0),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &privKey.PublicKey, privKey)
	if err != nil {
		panic(err)
	}
	return derBytes, privKey
}

func parsePrivateKey() *rsa.PrivateKey {
	privateKeyPEM := []byte(`-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDnNdbG0g7TYeoV
uCh6vFmOlkc95FHZoW3uNIiAWvoRbpOLE+21TkvNdtXoJ9JCpkM4uUX7TNBh3Nu5
ODxFFcFkJkM9Q2sWlU4rtrGlJ4w4jwMNuAKGdwAxXlpQjY7HYiouyY+1hXFY2Rwp
y+qMCjmXIhJWSR533bCTpZqgJJtYmJuvUAVjSAAxdLPVD98O35oejkAcyvcNKtpp
Tek8g70RbOEA/FG5S7uwhZbKTtJRBlu59YFCyESXqBISoFCtfJuFxfNk73SIHMXJ
chr9m2eAEhe7WFe8iYMwwVJYC44MKuZ5ONoco68NaHksJGOQyZ1LS8WLzuc0RvXO
YBFvjee/AgMBAAECggEADgIdDn67lzhfeQwR/R2xmgn7gax2U7vhb9qO9U04dBtB
pTOCkMbloNU1BekjvBYGt0ZtDwS1u2LTjS1IZDHP6G7JCXUu5SIL/RSx6VJevy6A
U4cf4AsQX+1aMMyNfKxd5z0fD9294vwvJfkiL3SPI1uqcL/isLB7JPbrn2Ltu+L6
+RF2/1zr48W+vs+7ZsdC5aZXJjGQWStguUy+43tMvfzZ1oPpWd3t2gyq7rvtwNys
tMJTvNUNMYi3t8oG8+SX289N9O2wNn+DxRKqNMoXuYoA72dC8xXL2zgdYY/ENOqU
UTcOLdB1bQgCnGWq1aDuz9zngY0HTlNYQ7tLtdI1wQKBgQD5YYKDlroSkPeoxFgc
f0bPtkJ7jV7lFrQrqcuUx4G2mz49Cp8bnhuh/sStkPJgTHPhPEx3GCOgOk8OZdel
I6RqJiv4H7HV5+zFlRH9Cq29hCLoXg6Lt0H0rcAEeYtm+xLbBEWBPB9xaRPDE9Yf
nz4/rxgXqgo65vq296bB+GBkVQKBgQDtWN0l77gDPrpuUUntd4b5Xu6eGZsZsffZ
ma0gsTae4NiwH8WUdzcq43M483XF9BUg0v+ovOcMIMq/5yBvJ3H/fQ4XMZPwiYK5
PyLJDUzK7pWfitYcKNIGy6V0yeGbgOzPua0RYpTheovATGG+JLUzm8pUED17miaD
J0zcM76PwwKBgA+kpTo55zwo6dAlWN2YwklfRnZXnN9D+FNQ2Fth1Gou/M15cBec
aGFWCOJWWE3gHdjAHo/N7NYtMi5WBxvty295K4LqAg7H+JtASZuU4ucjdckbtU/g
U/vUNlpRgYQZNcqVTwLXUaWckMfI48KiC5aVFi7N1MxzFsEJceVy/iDtAoGAD0H4
LXkklijRKUhWfUqCxcMhic5RlyxGp5lmdMSPo1UG+QOB2xJy3HH0tUOJXalcNlj6
EGncXH47Kmz8O8kIXgk2/6yzOvJMEgaKAOy29BC0U6ZEL1k8by1mPITB2RJHpu7j
vktdEMWk+D6wxd1sPJ4WOqM0oJ5/PU0odrto06sCgYA+v3IUfOlGKF8k0sVGa2Bv
HIg9UaV2mc2Ez3QKaQZuWQkvp3En0R0qH43AOJUZSfrTyG0r+75wNaPx2BdW/Vl7
DxfnYofClqL9p+Cx0dCdjtAdet+gQKMrmR8msRdFUv2thkHiM+b7dw3i0w/3ml3g
lsjfZy1kJouCLaJyMrWmsw==
-----END PRIVATE KEY-----`)

	block, _ := pem.Decode(privateKeyPEM)
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		panic(err)
	}
	return key.(*rsa.PrivateKey)
}

// 保存证书到PEM文件
func saveCertToFile(derBytes []byte, filename string) {
	// 创建文件句柄
	certOut, err := os.Create(filename)
	if err != nil {
		panic(fmt.Sprintf("无法创建证书文件: %v", err))
	}
	defer certOut.Close()

	// PEM编码并写入文件
	if err := pem.Encode(certOut, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	}); err != nil {
		panic(fmt.Sprintf("证书编码失败: %v", err))
	}

	fmt.Printf("证书已保存到: %s\n", filename)
}
func VerifyCert(caCertPath, targetCertPEM string) (string, bool, error) {
	// CA证书仍从文件加载
	caCert, err := loadCertFromFile(caCertPath)
	if err != nil {
		return "", false, fmt.Errorf("CA证书加载失败: %v", err)
	}

	// 目标证书从PEM字符串解析
	targetCert, err := parseCertFromPEM(targetCertPEM)
	if err != nil {
		return "", false, fmt.Errorf("目标证书解析失败: %v", err)
	}

	// 构建信任链（保持不变）
	roots := x509.NewCertPool()
	roots.AddCert(caCert)

	// 验证逻辑（保持不变）
	opts := x509.VerifyOptions{
		Roots:       roots,
		CurrentTime: time.Now(),
	}

	if _, err := targetCert.Verify(opts); err != nil {
		return formatPublicKey(targetCert), false, fmt.Errorf("证书链验证失败: %v", err)
	}

	// 补充验证项（保持不变）
	if !compareNames(caCert.Subject, targetCert.Issuer) {
		return formatPublicKey(targetCert), false,
			fmt.Errorf("颁发者信息不匹配\nCA Subject: %v\nTarget Issuer: %v",
				caCert.Subject, targetCert.Issuer)
	}

	if time.Now().After(targetCert.NotAfter) {
		return formatPublicKey(targetCert), false, fmt.Errorf("证书已过期")
	}

	return formatPublicKey(targetCert), true, nil
}

// 新增的PEM字符串解析函数
func parseCertFromPEM(pemData string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, fmt.Errorf("无效的PEM格式")
	}
	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("非证书类型的PEM块")
	}
	return x509.ParseCertificate(block.Bytes)
}
func formatPublicKey(cert *x509.Certificate) string {
	pubBytes, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return ""
	}
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubBytes,
	}))
}
func loadCertFromFile(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	for len(data) > 0 {
		block, rest := pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			return x509.ParseCertificate(block.Bytes)
		}
		data = rest
	}
	return nil, fmt.Errorf("文件中未找到PEM证书")
}
func compareNames(a, b pkix.Name) bool {
	// 深度比较颁发者字段
	return a.CommonName == b.CommonName &&
		compareStringSlices(a.Country, b.Country) &&
		compareStringSlices(a.Organization, b.Organization) &&
		compareStringSlices(a.OrganizationalUnit, b.OrganizationalUnit) &&
		compareStringSlices(a.Locality, b.Locality) &&
		compareStringSlices(a.Province, b.Province) &&
		a.SerialNumber == b.SerialNumber
}

// 辅助函数：比较字符串切片
func compareStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
