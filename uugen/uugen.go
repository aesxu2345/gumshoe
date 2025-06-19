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

package uugen

import (
	"crypto/sha256"
	"fmt"
	"strings"

	//"github.com/ulikunitz/xz"
	"encoding/binary"
	"strconv"
)

func Byte_in_UU(byin []byte) string {
	sha256_origin := sha256.Sum256([]byte("666I LOVE THIS GAME"))
	byin2 := padTo32Bytes(byin)
	sha256_origin = truncateTo32Bytes(byin2)

	fmt.Println("哈希", fmt.Sprintf("% x", sha256_origin), " 共 ", len(sha256_origin), " 字节")
	//这里开始有用
	var byte_256_cut_head4 [4]byte

	for i := range byte_256_cut_head4 {
		byte_256_cut_head4[i] = sha256_origin[i]
	} //8字节→16位
	time_low := byte_256_cut_head4
	fmt.Println("time_low是 ", fmt.Sprintf("% x", time_low), " 共 ", len(time_low), " 字节")

	var byte_256_cut_5_6 [2]byte
	for i := range byte_256_cut_5_6 {
		byte_256_cut_5_6[i] = sha256_origin[i+4]
	}
	//time_mid := byte_256_cut_5_6
	fmt.Println("哈希的后 16 位", fmt.Sprintf("% x", byte_256_cut_5_6), " 共 ", len(byte_256_cut_5_6), " 字节")
	time_mid := byte_256_cut_5_6

	fmt.Println("time_mid", fmt.Sprintf("% x", time_mid), " 共 ", len(time_mid), " 字节")

	var byte_256_cut_7_9 [3]byte
	for i := range byte_256_cut_7_9 {
		byte_256_cut_7_9[i] = sha256_origin[i+6]
	}
	fmt.Println("哈希的继续后 16 位", fmt.Sprintf("% x", byte_256_cut_7_9), " 共 ", len(byte_256_cut_7_9), " 字节")
	fmt.Println(byte_256_cut_7_9)
	ssto := "1j1j1"
	sstosp := strings.Split(ssto, "j")
	isaudai := 0
	for _, n := range byte_256_cut_7_9 {
		fmt.Printf("%08b ", n) // prints 00000000 11111101
		sstosp[isaudai] = fmt.Sprintf("%08b ", n)
		isaudai++
	}

	scasle := strings.Replace(fmt.Sprint(sstosp), "[", "", -1)
	scasle = strings.Replace(fmt.Sprint(scasle), "]", "", -1)
	scasle = strings.Replace(fmt.Sprint(scasle), " ", "", -1)
	fmt.Println("<>", scasle, "</>")
	u, err := strconv.ParseUint(scasle, 2, 32)
	if err != nil {
		panic(err)
	}
	fmt.Println(u)
	u = u >> 4
	fmt.Println(u)
	u2 := Uint64ToBytes(u)
	fmt.Println("u2是", fmt.Sprintf("% x", u2), " 共 ", len(u2), " 字节")
	newu2 := u2[:3]
	fmt.Println("newu2是", fmt.Sprintf("% x", newu2), " 共 ", len(newu2), " 字节")
	u3 := []byte("12")
	u3[0] = newu2[2]
	u3[1] = newu2[1]
	fmt.Println("u3是", fmt.Sprintf("% x", u3), " 共 ", len(u3), " 字节")
	u31 := strings.Split(fmt.Sprintf("% x", u3), " ")[0]
	fmt.Println(u31)
	u312 := u31[1:]
	fmt.Println(u312)
	u4 := fmt.Sprint(5, u312)
	fmt.Println(u4)
	dasafjfg := fmt.Sprint("0x", u4)
	fmt.Println(dasafjfg)
	nusadaam, err := strconv.ParseInt(dasafjfg, 0, 64)
	if err != nil {
		fmt.Println("转换错误:", err)
		return ""
	}
	fmt.Printf("16进制值: 0x%X\n十进制值: %d\n", nusadaam, nusadaam)
	u3[0] = byte(nusadaam)
	fmt.Println(u3)
	fmt.Println("u3是", fmt.Sprintf("% x", u3), " 共 ", len(u3), " 字节")
	time_hi_and_version := u3
	fmt.Println("time_hi_and_version是", fmt.Sprintf("% x", time_hi_and_version), " 共 ", len(time_hi_and_version), " 字节")
	fmt.Println()
	ct78 := sha256_origin[7:10]
	fmt.Println()
	fmt.Printf("ct78 % x", ct78)
	isaudai = 0
	for _, n := range ct78 {
		fmt.Printf("%08b ", n) // prints 00000000 11111101
		sstosp[isaudai] = fmt.Sprintf("%08b ", n)
		isaudai++
	}

	scasle = strings.Replace(fmt.Sprint(sstosp), "[", "", -1)
	scasle = strings.Replace(fmt.Sprint(scasle), "]", "", -1)
	scasle = strings.Replace(fmt.Sprint(scasle), " ", "", -1)
	fmt.Println("<s2>", scasle, "</>")
	scasle = fmt.Sprint("0011", scasle[4:])
	scasle = scasle[2:10]
	fmt.Println("<s3>", scasle, "</>")
	num, err := strconv.ParseUint(scasle, 2, 64)
	if err != nil {
		fmt.Println("解析失败:", err)
		return ""
	}
	clock_seq_hi_and_res := byte(uint(num))
	fmt.Println("clock_seq_hi_and_res是", fmt.Sprintf("% x", clock_seq_hi_and_res))
	ct810 := sha256_origin[8:10]
	fmt.Println()
	fmt.Printf("ct810是% x EOF", ct810)
	isaudai = 0
	ssto = "1j1"
	sstosp = strings.Split(ssto, "j")
	for _, n := range ct810 {
		fmt.Printf("%08b ", n) // prints 00000000 11111101
		sstosp[isaudai] = fmt.Sprintf("%08b ", n)
		isaudai++
	}
	fmt.Println("<s4>", sstosp, "</>")
	scasle = strings.Replace(fmt.Sprint(sstosp), "[", "", -1)
	scasle = strings.Replace(fmt.Sprint(scasle), "]", "", -1)
	scasle = strings.Replace(fmt.Sprint(scasle), " ", "", -1)
	fmt.Println("<s4>", scasle, "</>")
	scasle = scasle[2:]
	fmt.Println("<s4>", scasle, "</>")
	scasle = scasle[:8]
	fmt.Println("<s4>", scasle, "</>")
	num, err = strconv.ParseUint(scasle, 2, 64)
	if err != nil {
		fmt.Println("解析失败:", err)
		return ""
	}
	clock_seq_low := byte(uint(num))
	fmt.Println("clock_seq_low是", fmt.Sprintf("% x", clock_seq_low))
	ct11end := sha256_origin[9:16]

	fmt.Printf("ct11end是% x EOF", ct11end)
	ssto = "1j1j1j1j1j1j1j1j1"
	sstosp = strings.Split(ssto, "j")
	for _, n := range ct11end {
		fmt.Printf("%08b ", n) // prints 00000000 11111101
		sstosp[isaudai] = fmt.Sprintf("%08b ", n)
		isaudai++
	}
	sstosp = sstosp[2:]
	fmt.Println("<s5>", sstosp, "</>")
	scasle = strings.Replace(fmt.Sprint(sstosp), "[", "", -1)
	scasle = strings.Replace(fmt.Sprint(scasle), "]", "", -1)
	scasle = strings.Replace(fmt.Sprint(scasle), " ", "", -1)
	fmt.Println("<s6>", scasle, "</>")
	scasle = scasle[2:]
	fmt.Println("<s7>", scasle, "</>")
	scasle = scasle[:48]
	fmt.Println("<s8>", scasle, "</>")
	num, err = strconv.ParseUint(scasle, 2, 64)
	if err != nil {
		fmt.Println("解析失败:", err)
		return ""
	}
	fmt.Println("num", num)
	nodee := Uint64ToBytes(num)
	fmt.Println("nodee", nodee)
	nodee = nodee[:6]
	var nodeep [6]byte
	for icabua := range nodee {
		nodeep[icabua] = nodee[5-icabua]
	}
	for sadis := range nodeep {
		nodee[sadis] = nodeep[sadis]
	}

	fmt.Println("node是", fmt.Sprintf("% x", nodeep))
	str1 := strings.Replace(fmt.Sprintf("% x", time_low), " ", "", -1)
	str2 := strings.Replace(fmt.Sprintf("% x", time_mid), " ", "", -1)
	str3 := strings.Replace(fmt.Sprintf("% x", time_hi_and_version), " ", "", -1)
	str4 := strings.Replace(fmt.Sprintf("% x% x", clock_seq_hi_and_res, clock_seq_low), " ", "", -1)
	str5 := strings.Replace(fmt.Sprintf("% x", nodee), " ", "", -1)
	dafagafv := fmt.Sprint(str1, "-", str2, "-", str3, "-", str4, "-", str5)
	fmt.Println(dafagafv)
	return dafagafv
}
func Uint64ToBytes(val uint64) []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, val)

	return b
}

func padTo32Bytes(input []byte) []byte {
	// 创建32字节的切片（自动初始化为全0）
	padded := make([]byte, 32)

	// 将原始数据复制到新切片（仅复制有效部分）
	copy(padded, input)

	return padded
}

func truncateTo32Bytes(input []byte) [32]byte {
	var result [32]byte
	copy(result[:], input[:32]) // 安全截取前32字节
	return result
}
