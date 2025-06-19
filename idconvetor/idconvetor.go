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

package idconvetor

import (
	"bufio"
	"context"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"log"
	"math/rand"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/crypto/bcrypt"
)

const letters = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

/*
const saltA_list = "SaltA.list"
const saltB_list = "SaltB.list"
*/
func randStr(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

func randNumStr() int {
	letters := "1234567890"

	num := 900
	var err error
	for num > 800 {
		b := make([]byte, 3)
		for i := range b {
			b[i] = letters[rand.Intn(len(letters))]
		}
		num, err = strconv.Atoi(string(b))
		if err != nil {
			log.Fatal("转换失败:", err)
		}
	}
	return num
}

func GenerSalt(saltA_list string, saltB_list string) (string, string) {
	create_salt(saltA_list)
	create_salt(saltB_list)
	return saltA_list, saltB_list
}

func Gener_Salt_duel(iD_card string, saltA_list string, saltB_list string, s1h string, saltinA string, saltinB string) (string, string, []byte, string, string) {
	GenerSalt(saltA_list, saltB_list)
	fmt.Println(randNumStr())
	get1salt_BCrypt, err := readLine(randNumStr(), saltA_list)
	if err != nil {
		log.Fatal(err)
	}
	/*if !(len(saltinA) > 0) {
		get1salt_BCrypt = saltinA
	}*/
	if len(saltinA) > 0 {
		get1salt_BCrypt = saltinA // 仅在盐值有效时覆盖
	}
	fmt.Println("getsalt", get1salt_BCrypt)
	hash512 := GetSHA512HashCode(iD_card)
	fmt.Println(hash512)
	hash512 = hash512[:58]
	fmt.Println(hash512)
	saltHash1Hex := []byte("")
	unencodedSalt_return := []byte("")
	fmt.Println(unencodedSalt_return)
	if !(len(s1h) > 0) {
		var err error
		saltHash1Hex, unencodedSalt_return, err = bcrypt.GenerateFromPassword_return_salt([]byte(fmt.Sprint(hash512, get1salt_BCrypt)), 12)
		if err != nil {
			log.Fatal("BCryptFault", err)
		}

	}
	fmt.Println(saltHash1Hex)
	get2salt_sha256, err := readLine(randNumStr(), saltB_list)
	if err != nil {
		log.Fatal(err)
	}
	/*if !(len(saltinB) > 0) {
		get2salt_sha256 = saltinB
	}*/
	if len(saltinB) > 0 {
		get2salt_sha256 = saltinA // 仅在盐值有效时覆盖
	}
	saltHash1 := hex.EncodeToString(saltHash1Hex)
	fmt.Println(saltHash1)
	saltHash2 := GetSHA512HashCode(fmt.Sprint(saltHash1, get2salt_sha256))
	fmt.Println(saltHash2)
	/*for i := range 300 {
		if i == 0 {
			i++
		}
		getsalt, err := readLine(i, saltB_list)
		if err != nil {
			log.Fatal(err)
		}
		saltHash2_finder := GetSHA512HashCode(fmt.Sprint(saltHash1, getsalt))
		if strings.Contains(saltHash2_finder, saltHash2) {
			fmt.Println("founded")
		}

	}*/
	return saltHash1, saltHash2, unencodedSalt_return, get1salt_BCrypt, get2salt_sha256
}

func Gener_Salt_Replay(iD_card string, saltA_list string, saltB_list string, s1h string, bCsault []byte, saltinA string, saltinB string) (string, string, []byte) {
	GenerSalt(saltA_list, saltB_list)
	fmt.Println(randNumStr())
	getsalt := saltinA
	fmt.Println("getsalt", getsalt)
	hash512 := GetSHA512HashCode(iD_card)
	fmt.Println(hash512)
	hash512 = hash512[:58]
	fmt.Println(hash512)
	saltHash1Hex := []byte("")
	unencodedSalt_return := []byte("")
	fmt.Println(unencodedSalt_return)
	if !(len(s1h) > 0) {
		var err error
		saltHash1Hex, err = bcrypt.GenerateFromPassword_with_salt([]byte(fmt.Sprint(hash512, getsalt)), 12, bCsault)
		if err != nil {
			log.Fatal("BCryptFault", err)
		}

	}
	fmt.Println(saltHash1Hex)
	getsalt = saltinB
	saltHash1 := hex.EncodeToString(saltHash1Hex)
	fmt.Println(saltHash1)
	saltHash2 := GetSHA512HashCode(fmt.Sprint(saltHash1, getsalt))
	fmt.Println(saltHash2)
	/*for i := range 300 {
		if i == 0 {
			i++
		}
		getsalt, err := readLine(i, saltB_list)
		if err != nil {
			log.Fatal(err)
		}
		saltHash2_finder := GetSHA512HashCode(fmt.Sprint(saltHash1, getsalt))
		if strings.Contains(saltHash2_finder, saltHash2) {
			fmt.Println("founded")
		}

	}*/
	return saltHash1, saltHash2, unencodedSalt_return
}

func PathExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

func create_salt(target_file string) {
	fmt.Println(randStr(16))
	ifcrf, _ := PathExists(target_file)
	fmt.Println("bool is", ifcrf)
	if !ifcrf {
		_, e := os.Create(target_file)
		if e != nil {
			log.Fatal(e)
		}

		filePath := target_file // 文件路径
		// 打开文件，以追加模式打开或创建（如果文件不存在）
		file, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			fmt.Println("无法打开文件:", err)
			return
		}
		defer file.Close()
		var lines [800]string
		for i := range lines {
			lines[i] = randStr(14)
		}
		// 将每一行信息写入文件
		for _, line := range lines {
			_, err = fmt.Fprintln(file, line)
			if err != nil {
				fmt.Println("写入失败:", err)
				return
			}
		}
		fmt.Println("写入成功！")
	}
}
func readLine(lineNum int, filename string) (line string, err error) {
	file, err := os.Open(filename)
	if err != nil {
		return "", err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	currentLine := 1
	for scanner.Scan() {
		if currentLine == lineNum {
			return scanner.Text(), nil
		}
		currentLine++
	}

	if err := scanner.Err(); err != nil {
		return "", err
	}

	return "", fmt.Errorf("line %d not found", lineNum)
}

func GetSHA512HashCode(stringMessage string) string {

	message := []byte(stringMessage) //字符串转化字节数组
	//创建一个基于SHA512算法的hash.Hash接口的对象
	hash := sha512.New() //sha-512加密
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

/*
func Find_X_ID(origin_ID_str string, salt_list_file string, hash_for_compair string) bool {
	for i := 1; i <= 800; i++ {

		target_str, err := readLine(i, salt_list_file)
		if err != nil {
			log.Fatal(err)
		}
		byte_Temple1 := []byte(fmt.Sprint(GetSHA512HashCode(origin_ID_str)[:58], target_str))
		byte_Temple2, err := hex.DecodeString(hash_for_compair)
		if err != nil {
			log.Fatal(err)
		}
		if bcrypt.CompareHashAndPassword(byte_Temple2, byte_Temple1) == nil {
			return true
		}
	}
	return false
}
*/
// readAllSalts 读取盐列表文件的所有行
func readAllSalts(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var salts []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		salts = append(salts, strings.TrimSpace(scanner.Text()))
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return salts, nil
}

func Find_X_ID(origin_ID_str string, salt_list_file string, hash_for_compair string) bool {
	fmt.Println("origin_ID_str, salt_list_file , hash_for_compair分别是: ", origin_ID_str, salt_list_file, hash_for_compair)
	// 预加载所有盐到内存
	salts, err := readAllSalts(salt_list_file)
	if err != nil {
		log.Fatal(err)
		return false
	}

	// 预先计算SHA512(origin_ID_str)[:58]并转为字节数组
	hashPart := GetSHA512HashCode(origin_ID_str)[:58]
	hashPartBytes := []byte(hashPart)

	// 解码目标哈希
	targetHash, err := hex.DecodeString(hash_for_compair)
	if err != nil {
		log.Fatal(err)
		return false
	}

	// 并发控制
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var found bool
	var mux sync.Mutex

	// 设置Worker数量（根据CPU核心数调整）
	numWorkers := runtime.NumCPU()
	if numWorkers < 1 {
		numWorkers = 1
	}

	// 创建任务通道
	saltChan := make(chan string, len(salts))
	for _, s := range salts {
		saltChan <- s
	}
	close(saltChan)

	var wg sync.WaitGroup
	wg.Add(numWorkers)

	// 启动Worker协程
	for i := 0; i < numWorkers; i++ {
		go func() {
			defer wg.Done()
			for salt := range saltChan {
				select {
				case <-ctx.Done():
					return // 收到终止信号立即退出
				default:
					// 优化字符串拼接：直接操作字节数组
					saltBytes := []byte(salt)
					password := make([]byte, len(hashPartBytes)+len(saltBytes))
					copy(password, hashPartBytes)
					copy(password[len(hashPartBytes):], saltBytes)

					// 执行比较操作
					if bcrypt.CompareHashAndPassword(targetHash, password) == nil {
						mux.Lock()
						if !found {
							found = true
							cancel() // 触发全局终止
						}
						mux.Unlock()
						return
					}
				}
			}
		}()
	}

	wg.Wait()
	return found
}
