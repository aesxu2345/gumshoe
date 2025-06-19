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

package sigdifictor

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	gorsa "github.com/Lyafei/go-rsa"
	try_catch "github.com/golang-infrastructure/go-try-catch"
)

var (
	ErrInvalidBase64    = fmt.Errorf("invalid base64 encoding")
	ErrInvalidPEMFormat = fmt.Errorf("invalid PEM format")
)

func Gethash_fr(enc, public_key string) (string, error) {
	rtn, _ := gorsa.PublicDecrypt(enc, public_key)
	fmt.Println(rtn)
	pubdecrypt := rtn
	hexBytes_pubdecrypt := []byte(hex.EncodeToString([]byte(pubdecrypt)))
	fmt.Printf("hexBytes_pubdecrypt % x", hexBytes_pubdecrypt)
	fmt.Println()
	/*var val interface{}

	rest, err := asn1.Unmarshal(hexBytes_pubdecrypt, &val)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Parsed value: %v\n", val)
	fmt.Printf("Remaining bytes: % x\n", rest)
	hexStr := hex.EncodeToString(rest)
	fmt.Println(hexStr)*/
	hexBytes := hexBytes_pubdecrypt
	result := make([]byte, 0, len(hexBytes)/2)
	for i := 0; i < len(hexBytes); i += 2 {
		// 将两个Hex字符（如 '3'和'0'）组合为一个字节（如 0x30）
		highNibble := hexCharToByte(hexBytes[i])
		lowNibble := hexCharToByte(hexBytes[i+1])
		byteVal := (highNibble << 4) | lowNibble
		result = append(result, byteVal)
	}

	// 打印结果（格式化为Hex字符串，空格分隔）
	fmt.Printf("% x\n", result)
	if len(result) < 19+32 {
		try_catch.Try(func() { panic(fmt.Errorf("数据长度不足，无法提取SHA256哈希")) }).DefaultCatch(func(err error) {
			fmt.Println("other")
		}).Else(func() {
			fmt.Println("else")
		}).Finally(func() {
			fmt.Println("数据长度不足，无法提取SHA256哈希")
		}).Do()
	}
	if len(result) >= 19+32 {
		// 2. 跳过ASN.1头（前19字节），提取后32字节
		hash := result[19 : 19+32]
		//fmt.Printf("SHA256哈希值: %x\n", hash)
		return fmt.Sprintf("%x\n", hash), nil
	}
	return "", nil
}

func hexCharToByte(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10
	default:
		panic("非法的Hex字符")
	}
}
func GetSHA256HashCode(stringMessage string) string {

	message := []byte(stringMessage) //字符串转化字节数组
	//创建一个基于SHA256算法的hash.Hash接口的对象
	hash := sha256.New() //sha-256加密
	//hash := sha512.New() //SHA-512加密
	//输入数据
	hash.Write(message)
	//计算哈希值
	bytes := hash.Sum(nil)
	//将字符串编码为16进制格式,返回字符串
	hashCode := hex.EncodeToString(bytes)
	//返回哈希值
	return hashCode

}
