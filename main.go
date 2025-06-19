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

package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	__ "gumshoe/proto"
	teesign "gumshoe/teesign"
	"io"
	"log"
	lzmaquery "lzmaquery"
	mrand "math/rand"
	"net"
	"os"
	"reflect"
	sigdifictor "sigdifictor"
	"strconv"
	"strings"
	"sync"
	"time"

	flag "github.com/spf13/pflag"

	//"fmt"
	"io/ioutil"
	//	"log"
	_ "github.com/go-sql-driver/mysql"
	"github.com/google/uuid"

	"github.com/ulikunitz/xz"
	"golang.org/x/crypto/sha3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	cd59 "cd59"
	idconvetor "idconvetor"
	"net/http"
	uugen "uugen"

	try_catch "github.com/golang-infrastructure/go-try-catch"
	"golang.org/x/time/rate"
)

// var mutex sync.Mutex
var mutex sync.RWMutex

var Task_Pool string

var Life_Cycle_Order string

var teeStampCache = struct {
	sync.RWMutex
	m map[string]int64
}{m: make(map[string]int64)}

// 新增结构体
type ServerConfig struct {
	ListenAddr  string `json:"listen_addr"`   // 监听地址 ":6666"
	SSLCertPath string `json:"ssl_cert_path"` // SSL证书路径
	SSLKeyPath  string `json:"ssl_key_path"`  // SSL私钥路径
	DSN         string `json:"dsn"`           // 数据库DSN
	HMACKey     string `json:"hmac_key"`      // HMAC密钥
	AESKey      string `json:"aes_key"`       // AES密钥
	SaltAList   string `json:"salt_a_list"`   // SaltA路径
	SaltBList   string `json:"salt_b_list"`   // SaltB路径
	HTTPPort    string `json:"HTTPPort"`      // 新增：HTTP服务端口
}

// 新增全局变量和锁
var (
	serverConfig       *ServerConfig
	serverConfigOnce   sync.Once
	serverConfigMutex  sync.RWMutex
	serverConfigLoaded bool
)

// 定义服务端 实现 约定的接口
type HelloServiceServer struct {
	config *ServerConfig
}

var u = HelloServiceServer{}

// 实现 interface
func (s *HelloServiceServer) SayHello(ctx context.Context, req *__.HelloRequest) (resp *__.HelloReply, err error) {
	cfg := s.config
	name := req.Var1
	fmt.Printf("收到请求 Var1=%s\n", req.Var1)
	if name == "need_salt" {
		saA, saB := idconvetor.GenerSalt(cfg.SaltAList, cfg.SaltBList)
		lzA := lzma_coding(saA)
		lzB := lzma_coding(saB)
		fmt.Println("lzA是", lzA)
		fmt.Println("lzB是", lzB)
		resp = &__.HelloReply{Rpy1: "Hello salt", Rpy2: lzA, Rpy3: lzB}
	}
	if name == "ticket_given" {
		stmmp_pid, cgt, if_valid_token, err := vftoken(req.Var10, cfg.DSN)
		if err != nil || !if_valid_token {
			fmt.Println("无效的token: ", err)
			return resp, nil
		}
		var dcodaes string
		//var err error
		var full_hash string
		fmt.Println("1_ticket是: ", req.Var2)
		fmt.Println("req.Var3是:", req.Var3)
		ifexst, userUUID, ha1f512, ha2f512 := excsql_search_ha1f512(req.Var3, cfg.DSN)

		fmt.Println("hash是:", ha1f512, ha2f512)
		if !ifexst {
			fmt.Println("没有注册")
			resp = &__.HelloReply{Rpy1: "please_sign_for_an_id"}
			return resp, nil
		}
		full_hash = ""
		if ifexst {
			full_hash = fmt.Sprint(ha1f512, ha2f512)
		}
		fmt.Println("准备解密的密钥:", full_hash)
		dcodaes, err = decryptAES256CFB(full_hash, req.Var2)
		if err != nil {
			log.Println(err)
		}
		fmt.Println("aes解密: ", dcodaes)

		fmt.Print(`name == "ticket_given"末`, "\n")
		fmt.Println("req.Var4是", req.Var4)
		resp = &__.HelloReply{Rpy1: "permitted_request_waiting_for_backendservice_provider"}
		jmp, err := jSONToMap(req.Var4)
		if err != nil {
			fmt.Sprintln(err)
		}
		decoded, err := base64.StdEncoding.DecodeString(jmp["attention_cer"])
		if err != nil {
			log.Println(err)
		}
		decodestr := string(decoded)
		pkgt := ""
		var ifvld bool
		//var err error
		if len(jmp["attention_cer"]) > 0 {
			//jmp["attention_cer"] = ""

			pkgt, ifvld, err = teesign.VerifyCert("CA.cer", decodestr) //验证Attention
			if err != nil {
				fmt.Println(err)
				return resp, nil
			}

		}
		if !(len(jmp["attention_cer"]) > 0) {
			fmt.Println("无效数据, 当前AttentionKEY为必须值")
			goto LDADIFJSS
		}
		if ifvld {
			fmt.Println("tee可信pkgt是: <pubkey>", pkgt, "</pubkey>")
			sig_ori := jmp["tee_sig"]
			sig_ori = sig_ori[:len(sig_ori)-1]
			fmt.Println("tee_sig是: <tee_sig>", sig_ori, "</tee_sig>")
			gt56, err := sigdifictor.Gethash_fr(jmp["tee_sig"], pkgt)
			if err != nil {
				panic(err)
			}

			fmt.Println("gt56是: ", gt56)
			hashaaa := getSHA256HashCode(jmp["tee_stamp"])
			fmt.Println("hashaaa是: ", hashaaa)
			fmt.Println("cgt是", cgt)
			//数据库查找cgt
			/*stmmp_pid, _, if_pass, err := vftoken(req.Var10, cfg.DSN)
			if err != nil || !if_pass {
				fmt.Println("token验证不成功: ", err)
				return resp, nil
			}*/
			fmt.Println("时间戳", stmmp_pid)
			//时间戳对比
			stmmp := strings.Split(stmmp_pid, " ")
			ifstamp, err := isTimestampValid(stmmp[0])
			if !ifstamp || err != nil {
				fmt.Println("OTP超时或者非法时间戳")
				if err != nil {
					fmt.Print(err)
				}
				return resp, nil
			}
			fmt.Println("insert前jmp内容检查：", jmp)
			var devidu string
			if strings.Contains(gt56, hashaaa) {
				/*fmt.Println("tee返回正确")*/
				//devidu = uugen.Byte_in_UU([]byte(getSHA256HashCode(pkgt)))
				err := insertDeviceRelation(cfg.DSN, userUUID, devidu)
				if err != nil {
					fmt.Println("设备身份证匹配失败", err)
				}
				fmt.Println("TEE签名验证通过")

				// 获取当前时间戳
				//currentTS := time.Now().Unix()

				// 使用pkgt作为设备唯一标识
				teeStampCache.RLock()
				firstTS, exists := teeStampCache.m[pkgt]
				teeStampCache.RUnlock()

				if exists {
					r2eceivedTS, _ := strconv.ParseInt(jmp["tee_stamp"], 10, 64)
					fmt.Printf("第二次请求记录时间戳：%d\n", r2eceivedTS)
					if time.Now().Unix()-firstTS > 30 {
						teeStampCache.Lock()
						delete(teeStampCache.m, pkgt)
						teeStampCache.Unlock()
						fmt.Println("时间戳缓存过期，需重新同步")
						return &__.HelloReply{Rpy1: "timestamp_sync_expired"}, nil
					}

					// 保持原有时间差计算逻辑
					currentTS := time.Now().Unix()
					timeDiff := currentTS - firstTS

					fmt.Printf("时间差验证：%d秒 (服务端时间差)\n", timeDiff)
					fmt.Printf("首次记录服务端时间：%d\n", firstTS)
					fmt.Printf("当前服务端时间：%d\n", currentTS)

					const (
						minDiff = 5  // 最小允许间隔
						maxDiff = 60 // 最大允许间隔（可扩展至20秒）
					)

					if timeDiff < minDiff || timeDiff > maxDiff { // 严格秒窗口
						fmt.Println("时间戳验证失败：非法的时间间隔")
						teeStampCache.Lock()
						delete(teeStampCache.m, pkgt)
						teeStampCache.Unlock()
						return resp, nil
					}

					fmt.Println("时间戳验证通过，执行设备绑定...")
					devidu := uugen.Byte_in_UU([]byte(getSHA256HashCode(pkgt)))
					if err := insertDeviceRelation(cfg.DSN, userUUID, devidu); err != nil {
						fmt.Println("设备绑定失败:", err)
					}

					teeStampCache.Lock()
					delete(teeStampCache.m, pkgt)
					teeStampCache.Unlock()

				} else {
					// 第一次请求 - 存储时间戳
					serverFirstTS := time.Now().UTC().Unix()
					fmt.Printf("第一次请求记录时间戳：%d\n", serverFirstTS)
					// 同时验证客户端时间戳合理性（非必须但推荐）
					/*clientTS, _ := strconv.ParseInt(jmp["tee_stamp"], 10, 64)
					if clientTS > serverFirstTS+5 || clientTS < serverFirstTS-300 {
						fmt.Printf("客户端时间戳异常：客户端=%d 服务端=%d\n", clientTS, serverFirstTS)
						return resp, fmt.Errorf("timestamp validation failed")
					}*/
					teeStampCache.Lock()
					teeStampCache.m[pkgt] = serverFirstTS
					teeStampCache.Unlock()

					fmt.Printf("首次请求记录服务端时间戳：%d\n", serverFirstTS)
					return &__.HelloReply{
						Rpy1: "timestamp_sync_required",
						Rpy2: strconv.FormatInt(serverFirstTS, 10), // 返回服务端时间供客户端验证
					}, nil
				}
			}
			if !strings.Contains(gt56, hashaaa) {
				fmt.Println("无效TEE数据, 非法录入")
				goto LDADIFJSS
			}
			devidu = uugen.Byte_in_UU([]byte(getSHA256HashCode(pkgt)))
			time.Sleep(10 * time.Second)
			fmt.Println("<要插入的所有字段是含devidu>")
			fmt.Println("要插入的所有字段是:", devidu, pkgt, jmp["smbios"], jmp["disk_info"], jmp["gpu_info"], jmp["ens_info"])
			fmt.Println("</要插入的所有字段是含devidu>")
			time.Sleep(30 * time.Second)
			ex_insert, err := lzmaquery.QueryDevicesByHashes(cfg.DSN, pkgt, jmp["smbios"], jmp["disk_info"], jmp["gpu_info"], jmp["ens_info"])
			if err != nil {
				fmt.Println(err)
			}
			if len(ex_insert) > 0 {
				fmt.Println("err! 重复插入数据")
			}
			ex_insert, _ = lzmaquery.QueryDevicesByHashes(cfg.DSN, pkgt, "", "", "", "")
			if !(len(ex_insert) > 0) {
				fmt.Println("devidu是: ", devidu)
				if devidu == "" {
					panic("设备UUID为空")
				}
				lzmaquery.HandleDeviceDetails(cfg.DSN, devidu, pkgt, "", "", "", "")
			}
			ex_insert, _ = lzmaquery.QueryDevicesByHashes(cfg.DSN, "", jmp["smbios"], "", "", "")
			if !(len(ex_insert) > 0) && len(jmp["smbios"]) > 0 {
				lzmaquery.HandleDeviceDetails(cfg.DSN, devidu, "", jmp["smbios"], "", "", "")
			}
			ex_insert, _ = lzmaquery.QueryDevicesByHashes(cfg.DSN, "", "", jmp["disk_info"], "", "")
			if !(len(ex_insert) > 0) && len(jmp["disk_info"]) > 0 {
				lzmaquery.HandleDeviceDetails(cfg.DSN, devidu, "", "", jmp["disk_info"], "", "")
			}
			fmt.Println("999999999999999999999999999999999999999999999999")
			ex_insert, _ = lzmaquery.QueryDevicesByHashes(cfg.DSN, "", "", "", jmp["gpu_info"], "")
			if !(len(ex_insert) > 0) && len(jmp["disk_info"]) > 0 {
				lzmaquery.HandleDeviceDetails(cfg.DSN, devidu, "", "", "", jmp["gpu_info"], "")
			}
			ex_insert, _ = lzmaquery.QueryDevicesByHashes(cfg.DSN, "", "", "", "", jmp["ens_info"])
			if !(len(ex_insert) > 0) && len(jmp["ens_info"]) > 0 {
				lzmaquery.HandleDeviceDetails(cfg.DSN, devidu, "", "", "", "", jmp["ens_info"])
			}
		}
	LDADIFJSS:
	}
	if name == "sign_for" {
		//fmt.Println("身份证号是: ", req.Var2)
		fmt.Println("sh2是:", req.Var2)

		/*tto_s2 := []byte("11111111111111111111111111111111111111111111111111111111111111111111111111111111111111")
		to_s2 := sha256.Sum256([]byte(saha2))
		//icddd := fmt.Sprint(req.Var3)
		fmt.Println("111")
		for i := range to_s2 {
			tto_s2[i] = to_s2[i]
		}*/
		//fdd, _, _, _ := excsql_search_ha1f512(saha2_1, cfg.DSN)

		// if req.Var4
		tto_id, _, err := generateIDHMAC(cfg.HMACKey, req.Var4)
		tto_id_UU := uugen.Byte_in_UU(tto_id)
		fmt.Println(`Byte_in_UU(tto_id)是`, tto_id_UU)
		fdd, _, _, _ := excsql_search_UU(tto_id_UU, cfg.DSN)
		if fdd {
			fmt.Println("user_existed")
			resp = &__.HelloReply{Rpy1: "user_existed"}
			//return resp, fmt.Errorf("user_exist")
			return resp, nil
		}
		if err != nil {
			log.Fatal("HMAC-sha256生成失败", err)
		}
		bCsalt_read, err := base64.StdEncoding.DecodeString(req.Var5)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf(`bCsalt_read接受数据byte % x\n`, bCsalt_read)
		fmt.Println()
		sh1, saha2, _ := idconvetor.Gener_Salt_Replay(req.Var4, cfg.SaltAList, cfg.SaltBList, "", bCsalt_read, req.Var6, req.Var7)
		//saha2 := fmt.Sprint(req.Var2)
		fmt.Println("PaddedHash2即saha2是: ", saha2)
		saha2_1 := saha2[:len(saha2)/2]
		fmt.Println("saha2_1是:", saha2_1)
		saha2_2 := saha2[len(saha2)/2:]
		fmt.Println("sh1是", sh1, "req.Var3是", req.Var3)
		if !strings.Contains(sh1, req.Var3) {
			fmt.Println("垃圾数据")
			return resp, nil
		}
		if strings.Contains(sh1, req.Var3) {
			fmt.Println("数据校验通过")
		}
		//resp = &__.HelloReply{Rpy1: "new_paddedhaash2_generated", Rpy2: saha2}
		fmt.Println("req.Var10是: ", req.Var10)
		stmmp_pid, _, if_pass, err := vftoken(req.Var10, cfg.DSN)
		if err != nil || !if_pass {
			fmt.Println("token验证不成功: ", err)
			return resp, nil
		}
		fmt.Println("时间戳", stmmp_pid)
		//时间戳对比
		stmmp := strings.Split(stmmp_pid, " ")
		ifstamp, err := isTimestampValid(stmmp[0])
		if !ifstamp || err != nil {
			fmt.Println("OTP超时或者非法时间戳")
			if err != nil {
				fmt.Print(err)
			}
			return resp, nil
		}
		fmt.Println("开始插入")
		shake_source, err := shake256Hash(saha2)
		if err != nil {
			log.Fatal("shake256Hash出错", err)
		}
		shake_UU := uugen.Byte_in_UU(shake_source)
		saha2_1 = shake_UU
		resp = &__.HelloReply{Rpy1: "you_have_been_signin_success", Rpy2: fmt.Sprint(saha2_1, " ", saha2_2)}
		insertHolderXID(uugen.Byte_in_UU(tto_id), saha2_1, saha2_2, cfg.DSN)
	}
	if name == "with_fingerprint" {
		var err error
		stmmp_pid, _, if_valid_token, err := vftoken(req.Var10, cfg.DSN)
		if err != nil || !if_valid_token {
			fmt.Println("无效的token: ", err)
			return resp, nil
		}
		stmmp := strings.Split(stmmp_pid, " ")
		ifstamp, err := isTimestampValid(stmmp[0])
		if !ifstamp || err != nil {
			fmt.Println("OTP超时或者非法时间戳")
			if err != nil {
				fmt.Print(err)
			}
			return resp, nil
		}
		//var jmp map[string]string
		var decoded []byte
		var decodestr string
		pkgt := ""
		var ifvld bool
		fmt.Println(`req.Var4是: `, req.Var4)
		jmp := make(map[string]string)
		jmp["ens_info"] = ""
		jmp["smbios"] = ""
		jmp["gpu_info"] = ""
		jmp["disk_info"] = ""
		jmp, err = jSONToMap(req.Var4)
		if err != nil {
			log.Println(err)
		}

		decoded, err = base64.StdEncoding.DecodeString(jmp["attention_cer"])
		decodestr = string(decoded)
		if err != nil {
			log.Println(err)
		}

		//var ifvld bool
		if len(jmp["attention_cer"]) > 0 {
			//jmp["attention_cer"] = ""

			pkgt, ifvld, err = teesign.VerifyCert("CA.cer", decodestr) //验证Attention
			if err != nil {
				fmt.Println(err)
				return resp, nil
			}
		}

		if ifvld {
			gt56, err := sigdifictor.Gethash_fr(jmp["tee_sig"], pkgt)
			if err != nil {
				panic(err)
			}
			hashaaa := getSHA256HashCode(jmp["tee_stamp"])
			if strings.Contains(gt56, hashaaa) {

			}
		}
		//devidu := uugen.Byte_in_UU([]byte(getSHA256HashCode(pkgt)))
		//if len(pkgt) > 0 {
		//pkgt = ""
		//}
		/*if len(jmp["smbios"]) > 0 {
			jmp["smbios"] = ""
		}
		if len(jmp["gpu_info"]) > 0 {
			jmp["gpu_info"] = ""
		}
		fmt.Println("fing999")
		if len(jmp["disk_info"]) > 0 {
			jmp["disk_info"] = ""
		}
		if len(jmp["ens_info"]) > 0 {
			jmp["ens_info"] = ""
		}*/
		fmt.Println("jmp的内容: ", jmp)

		teeFingerprint := jmp["attention_cer"]

		if teeFingerprint == "" {
			// 回退逻辑（如有必要）
			//teeFingerprint = jmp["tee_sig"]
			try_catch.Try(func() { panic("TEE为空") }).DefaultCatch(func(err error) {
				fmt.Println("other")
			}).Finally(func() {
				fmt.Println("finally")
			}).Do()
		}

		fmt.Println("TEE是: ", teeFingerprint)

		//rtust, err := lzmaquery.QueryDevicesByHashes(cfg.DSN, pkgt, jmp["smbios"], jmp["disk_info"], jmp["gpu_info"], jmp["ens_info"])
		rtust, err := lzmaquery.QueryDevicesByHashes(cfg.DSN, pkgt, jmp["smbios"], jmp["hhd_info"], jmp["gpu_info"], jmp["ens_info"])
		if err != nil {
			fmt.Println(err)
		}
		fmt.Println("查到的设备id是", rtust)
		// 新增：获取shake_256_rehashUU_122值
		holderUUID, err := GetHolderUUIDByDeviceUUID(cfg.DSN, rtust)
		if err != nil {
			log.Printf("查询持有者UUID失败: %v", err)
			holderUUID = rtust // 回退到设备UUID
		}
		rtust = holderUUID // rtust现在直接是持有者UUID
		fmt.Println("stmmp[0]是", stmmp[0])
		fmt.Println("stmmp[1]是", stmmp[1])
		mutex.Lock()
		mapout := make(map[string]string)
		if len(Task_Pool) > 0 {
			mapout = Dimming_Map(Task_Pool)
		}
		mapout[Encode_to_B64(stmmp[1])] = Encode_to_B64(rtust)
		Task_Pool = Dedim_Map(mapout)
		clear(mapout)
		if len(Life_Cycle_Order) > 0 {
			mapout = Dimming_Map(Life_Cycle_Order)
		}
		unixSeconds := time.Now().Unix()
		mapout[Encode_to_B64(stmmp[1])] = Encode_to_B64(fmt.Sprintf("%d", unixSeconds))
		Life_Cycle_Order = Dedim_Map(mapout)
		mutex.Unlock()
		/*wbpp, err := GetWebhookByCGT(cfg.DSN, cgtt)
		if err != nil {
			fmt.Println(err)
		}
		statusCode, err := SendToWebhook(wbpp, rtust, 5*time.Second)
		if err != nil {
			log.Printf("Webhook发送失败！状态码:%d 错误:%v", statusCode, err)
		}
		log.Printf("Webhook发送成功！状态码:%d", statusCode)*/
	}
	err = nil
	return resp, nil
}

// 启动服务
func main() {
	fmt.Println("SaferMutex")
	var configFile string
	var genvisitor bool
	var gensuperior bool
	flag.StringVarP(&configFile, "config", "c", "config.conf", "服务端配置文件路径")
	flag.BoolVarP(&genvisitor, "genvisitor", "G", false, "服务端配置文件路径")
	flag.BoolVarP(&gensuperior, "super", "S", false, "服务端配置文件路径")
	flag.Parse()

	if err := serverConfig.initServerConfig(configFile); err != nil {
		log.Fatalf("初始化服务端配置失败: %v", err)
	}
	cfg, err := getServerConfig()
	if err != nil {
		log.Fatalf("获取服务端配置失败: %v", err)
	}
	if genvisitor {
		tab_name := "visitors"
		if gensuperior {
			tab_name = "admins"
		}
		pvk, pb, err := generateKeyPair("")
		if err != nil {
			fmt.Println(err)
		}
		fmt.Println("私钥是", pvk)
		sz2 := []byte("11111111111111111111111111111111111111111111111111111111111111111111111111111111111111")
		sz1 := sha256.Sum256([]byte(pb))
		for ijsdaf := range sz1 {
			sz2[ijsdaf] = sz1[ijsdaf]
		}
		pubuu := uugen.Byte_in_UU(sz2)
		err = insertAuthRecord(cfg.DSN, pubuu, pb, "", tab_name)
		if err != nil {
			fmt.Println(err)
		}
	}
	go func() {
		try_catch.Try(func() {
			initialData := map[string]string{
				"status":  "running",
				"version": "1.0.0",
			}

			// 创建服务实例
			service := NewHTTPService(
				initialData,
				&Task_Pool,
				&Life_Cycle_Order,
				&mutex,
				cfg, // 传递服务器配置
			)

			//启动http服务
			if err := service.Start(cfg.HTTPPort); err != nil {
				panic(err)
			}
		}).DefaultCatch(func(err error) {
			fmt.Println("other")
		}).Finally(func() {
			fmt.Println("finally")
		}).Do()
	}()
	go func() {
		for {
			time.Sleep(5 * time.Second)
			mutex.Lock() // 所有锁操作集中在这里
			if Life_Cycle_Order == "e30=" {
				Life_Cycle_Order = ""
			}
			if Task_Pool == "e30=" {
				Task_Pool = ""
			}
			if Life_Cycle_Order != "" {
				lifeCycleMap := Dimming_Map(Life_Cycle_Order)
				taskMap := Dimming_Map(Task_Pool)
				fmt.Println("Life_Cycle_Order: ", Life_Cycle_Order)
				fmt.Println("Task_Pool: ", Task_Pool)
				fmt.Println("lifeCycleMap: ", lifeCycleMap)
				fmt.Println("taskMap: ", taskMap)
				for pid, encodedTime := range lifeCycleMap {
					timestamp, err := strconv.ParseInt(DecodeB64(encodedTime), 10, 64)
					if err != nil {
						log.Println("时间戳解析错误:", err)
						continue
					}

					expiration := time.Unix(timestamp, 0).Add(5 * time.Minute)
					if time.Now().After(expiration) {
						delete(taskMap, pid)
						delete(lifeCycleMap, pid)
					}
				}

				Task_Pool = Dedim_Map(taskMap)
				Life_Cycle_Order = Dedim_Map(lifeCycleMap)
			}

			mutex.Unlock()
		}
	}()
	creds, err := credentials.NewServerTLSFromFile(cfg.SSLCertPath, cfg.SSLKeyPath)
	// 2. 启动带TLS的grpc服务
	s := grpc.NewServer(grpc.Creds(creds))
	if err != nil {
		log.Fatalf("加载TLS证书失败: %v", err)
	}
	// 创建带配置的服务实例
	serverInstance := &HelloServiceServer{config: cfg}

	// 注册服务时传入带配置的实例
	__.RegisterHelloServiceServer(s, serverInstance)
	// 加载SSL证书

	// 1. 添加监听的端口
	port := cfg.ListenAddr
	l, err := net.Listen("tcp", port)
	if err != nil {
		log.Fatalf("端口监听错误 : %v\n", err)
	}
	fmt.Printf("正在SSL监听： %s 端口\n", port)

	// 3. 注册服务（保持不变）
	//__.RegisterHelloServiceServer(s, &u)

	if err := s.Serve(l); err != nil {
		log.Fatalf("服务启动失败: %v", err)
	}
}

func lzma_coding(filePath string) string {
	// 1. 读取 TXT 文件为 []byte
	//filePath := "example.txt"
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		log.Fatalf("读取文件失败: %v", err)
	}

	// 2. LZMA 压缩
	compressedData, err := compressLZMA(data)
	if err != nil {
		log.Fatalf("LZMA 压缩失败: %v", err)
	}

	// 3. 将 []byte 转为 Hex 字符串
	hexStr := fmt.Sprintf("%x", compressedData)

	// 4. 用 fmt.Sprint 转换为字符串（这里 hexStr 已经是字符串）
	result := fmt.Sprint(hexStr)

	// 输出结果
	fmt.Println("原始数据长度:", len(data))
	fmt.Println("压缩后数据长度:", len(compressedData))
	fmt.Println("Hex 字符串:", result)
	return result
}

/*func compressLZMA(data []byte) ([]byte, error) {
	var buf bytes.Buffer

	// 创建 LZMA 配置（使用默认参数）
	cfg := &lzma.WriterConfig{
		DictCap: 8 * 1024 * 1024, // 8MB 字典大小
	}

	// 通过配置创建写入器
	w, err := cfg.NewWriter(&buf)
	if err != nil {
		fmt.Printf("!! LZMA写入器创建失败 | 错误: %v\n", err)
		return nil, fmt.Errorf("lzma writer creation failed: %v", err)
	}

	if _, err = w.Write([]byte(data)); err != nil {
		fmt.Printf("!! LZMA压缩写入失败 | 数据长度: %d | 错误: %v\n", len(data), err)
		return nil, fmt.Errorf("compression write failed: %v", err)
	}

	if err = w.Close(); err != nil {
		fmt.Printf("!! LZMA写入器关闭失败 | 错误: %v\n", err)
		return nil, fmt.Errorf("lzma writer close failed: %v", err)
	}

	return buf.Bytes(), nil
}*/

func compressLZMA(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	w, err := xz.NewWriter(&buf)
	fmt.Print(err)
	if _, err := w.Write(data); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func insertHolderXID(uuidStr, hash1, hash2, dsn string) bool {
	// 建立数据库连接
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		log.Printf("[插入失败] 连接数据库错误 | DSN: %s | 错误: %v", dsn, err)
		return false
	}
	defer db.Close()

	// 准备插入语句（使用参数化查询防止SQL注入）
	stmt, err := db.Prepare(`
        INSERT INTO holder_X_ID (
            device_holder_ID_card_UUID,
            shake_256_rehashUU_122,
            devided_2_half_512
        ) VALUES (?, ?, ?)
    `)
	if err != nil {
		log.Printf("[插入失败] 准备SQL语句错误 | 错误: %v", err)
		return false
	}
	defer stmt.Close()

	// 执行插入操作
	result, err := stmt.Exec(uuidStr, hash1, hash2)
	if err != nil {
		log.Printf("[插入失败] 执行插入错误 | UUID: %s | 错误: %v", uuidStr, err)
		return false
	}

	// 验证影响行数
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected != 1 {
		log.Printf("[插入失败] 未影响预期行数 | 实际影响行数: %d", rowsAffected)
		return false
	}

	return true
}

func valid_if_pem(cA_pem string, target_cert_pem string, check_expire bool) bool {
	// 解析 CA 证书
	caBlock, _ := pem.Decode([]byte(cA_pem))
	if caBlock == nil {
		fmt.Println("CA PEM decode failed")
		return false
	}
	caCert, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		fmt.Println("CA cert parse error:", err)
		return false
	}

	// 创建证书池并添加 CA 证书
	pool := x509.NewCertPool()
	pool.AddCert(caCert)

	// 解析目标证书
	targetBlock, _ := pem.Decode([]byte(target_cert_pem))
	if targetBlock == nil {
		fmt.Println("Target PEM decode failed")
		return false
	}
	targetCert, err := x509.ParseCertificate(targetBlock.Bytes)
	if err != nil {
		fmt.Println("Target cert parse error:", err)
		return false
	}

	// 验证证书链
	verifyOptions := x509.VerifyOptions{
		Roots: pool,
	}

	if _, err := targetCert.Verify(verifyOptions); err != nil {
		fmt.Println("Certificate verification failed:", err)
		return false
	}

	// 检查有效期
	if check_expire {
		now := time.Now()
		if now.Before(targetCert.NotBefore) {
			fmt.Println("Certificate not yet valid")
			return false
		}
		if now.After(targetCert.NotAfter) {
			fmt.Println("Certificate expired")
			return false
		}
	}

	return true
}

func encryptAES256CFBWithIV(key string, text string, iv []byte) (string, error) {
	// 将密钥转换为32字节的哈希
	keyBytes := sha256.Sum256([]byte(key))

	// 创建AES cipher
	block, err := aes.NewCipher(keyBytes[:])
	if err != nil {
		return "", err
	}

	// 处理 IV 逻辑
	if iv == nil {
		// 如果未传入 IV，生成随机 IV
		iv = make([]byte, aes.BlockSize)
		if _, err := io.ReadFull(rand.Reader, iv); err != nil {
			return "", err
		}
	} else {
		// 检查传入的 IV 长度是否正确
		if len(iv) != aes.BlockSize {
			return "", fmt.Errorf("IV 必须为 %d 字节", aes.BlockSize)
		}
	}

	// 创建 CFB 加密器
	stream := cipher.NewCFBEncrypter(block, iv)

	// 加密数据
	ciphertext := make([]byte, len(text))
	stream.XORKeyStream(ciphertext, []byte(text))

	// 合并 IV 和密文
	result := make([]byte, len(iv)+len(ciphertext))
	copy(result[:aes.BlockSize], iv)
	copy(result[aes.BlockSize:], ciphertext)

	// 返回 Base64 编码结果
	return base64.StdEncoding.EncodeToString(result), nil
}

// 原函数保持兼容（自动生成 IV）
func encryptAES256CFB(key string, text string) (string, error) {
	return encryptAES256CFBWithIV(key, text, nil)
}

func decryptAES256CFB(key string, encryptedText string) (string, error) {
	// 将密钥转换为32字节的哈希
	keyBytes := sha256.Sum256([]byte(key))

	// 解码 Base64
	data, err := base64.StdEncoding.DecodeString(encryptedText)
	if err != nil {
		return "", err
	}

	// 检查数据长度
	if len(data) < aes.BlockSize {
		return "", errors.New("密文太短")
	}

	// 分离 IV 和密文
	iv := data[:aes.BlockSize]
	ciphertext := data[aes.BlockSize:]

	// 创建 AES cipher
	block, err := aes.NewCipher(keyBytes[:])
	if err != nil {
		return "", err
	}

	// 创建 CFB 解密器
	stream := cipher.NewCFBDecrypter(block, iv)

	// 解密数据
	plaintext := make([]byte, len(ciphertext))
	stream.XORKeyStream(plaintext, ciphertext)

	return string(plaintext), nil
}
func generateIDHMAC(keyStr string, idCard string) ([]byte, string, error) {
	// 1. 验证密钥长度
	if len([]byte(keyStr)) != 32 {
		return nil, "", fmt.Errorf("密钥必须为 32 字节，当前长度: %d 字节", len([]byte(keyStr)))
	}

	// 2. 归一化身份证号
	normalizedID := strings.ToUpper(strings.ReplaceAll(idCard, " ", ""))

	// 3. 转换密钥类型
	key := []byte(keyStr)

	// 4. 计算 HMAC-SHA256
	h := hmac.New(sha256.New, key)
	h.Write([]byte(normalizedID))
	hashBytes := h.Sum(nil)

	// 5. 转换为十六进制字符串
	hexString := hex.EncodeToString(hashBytes)

	return hashBytes, hexString, nil
}
func excsql_search_ha1f512(targetHash string, dsn string) (found bool, uuid string, hash1 string, hash2 string) {
	// 自动初始化零值：found=false, uuid="", hash1="", hash2=""

	db, err := sql.Open("mysql", dsn)
	if err != nil {
		log.Printf("[查询失败] 连接错误 | DSN: %s | 错误: %v", dsn, err)
		return // 自动返回初始化的零值
	}
	defer db.Close()

	// 使用结构体提高可读性（可选）
	type HolderRecord struct {
		UUID  string
		Hash1 string
		Hash2 string
	}

	var record HolderRecord
	err = db.QueryRow(
		`SELECT device_holder_ID_card_UUID, 
                shake_256_rehashUU_122, 
                devided_2_half_512 
         FROM holder_X_ID 
         WHERE shake_256_rehashUU_122 = ?`,
		targetHash,
	).Scan(&record.UUID, &record.Hash1, &record.Hash2)

	switch {
	case err == sql.ErrNoRows:
		log.Printf("[查询] 未找到记录 | 目标哈希: %s", targetHash)
		return
	case err != nil:
		log.Printf("[查询失败] 数据库错误 | 哈希: %s | 错误: %v", targetHash, err)
		return
	default:
		return true, record.UUID, record.Hash1, record.Hash2
	}
}
func excsql_search_UU(targetUUID, dsn string) (found bool, uuidStr, hash1, hash2 string) {
	// 参数校验
	if _, err := uuid.Parse(targetUUID); err != nil {
		log.Printf("无效的 UUID 格式: %s", targetUUID)
		return
	}

	// 建立数据库连接
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		log.Printf("数据库连接失败: %v", err)
		return
	}
	defer db.Close()

	// 执行查询（直接使用字符串匹配）
	query := `
        SELECT 
            device_holder_ID_card_UUID,
            shake_256_rehashUU_122,
            devided_2_half_512 
        FROM holder_X_ID 
        WHERE device_holder_ID_card_UUID = ?`

	var (
		dbUUID  sql.NullString
		dbHash1 sql.NullString
		dbHash2 sql.NullString
	)

	// 参数绑定为字符串
	err = db.QueryRow(query, targetUUID).Scan(&dbUUID, &dbHash1, &dbHash2)
	switch {
	case err == sql.ErrNoRows:
		log.Printf("未找到记录 | UUID: %s", targetUUID)
		return
	case err != nil:
		log.Printf("查询失败: %v", err)
		return
	}

	// 返回结果
	return true, dbUUID.String, dbHash1.String, dbHash2.String
}

func shake256Hash(inputHex string) ([]byte, error) {
	// 解码输入的十六进制字符串
	data, err := hex.DecodeString(inputHex)
	if err != nil {
		return nil, fmt.Errorf("hex decode failed: %w", err)
	}

	// 初始化 SHAKE256 哈希实例
	shakeHash := sha3.NewShake256()
	if _, err := shakeHash.Write(data); err != nil {
		return nil, fmt.Errorf("shake256 write failed: %w", err)
	}

	// 计算需要读取的字节数：122 比特 = 15 字节（120 比特） + 最后 2 比特
	// 因此总共需要读取 16 字节，处理最后的 2 比特
	output := make([]byte, 16)
	if _, err := shakeHash.Read(output); err != nil {
		return nil, fmt.Errorf("shake256 read failed: %w", err)
	}

	// 将最后一个字节的无效位清零（保留高 2 比特，其余置零）
	output[15] &= 0xC0 // 0xC0 = 二进制 11000000

	return output, nil
}
func (c *ServerConfig) initServerConfig(configFilePath string) error {
	var initErr error
	serverConfigOnce.Do(func() {
		serverConfigMutex.Lock()
		defer serverConfigMutex.Unlock()

		file, err := os.Open(configFilePath)
		if err != nil {
			initErr = fmt.Errorf("配置文件打开失败: %v", err)
			return
		}
		defer file.Close()

		decoder := json.NewDecoder(file)
		decoder.DisallowUnknownFields()

		tempConfig := &ServerConfig{}
		if err := decoder.Decode(tempConfig); err != nil {
			initErr = fmt.Errorf("配置解析失败: %v", err)
			return
		}

		// 验证必填字段
		if tempConfig.ListenAddr == "" {
			initErr = errors.New("listen_addr 不能为空")
			return
		}
		if tempConfig.SSLCertPath == "" || tempConfig.SSLKeyPath == "" {
			initErr = errors.New("SSL证书路径和私钥路径必须配置")
			return
		}

		if tempConfig.HTTPPort == "" {
			initErr = errors.New("http_port 必须配置")
			return
		}
		serverConfig = tempConfig
		serverConfigLoaded = true
	})
	return initErr
}

// 安全获取配置
func getServerConfig() (*ServerConfig, error) {
	serverConfigMutex.RLock()
	defer serverConfigMutex.RUnlock()

	if !serverConfigLoaded {
		return nil, errors.New("服务端配置未初始化")
	}
	return serverConfig, nil
}
func queryVisitorByAPIToken(dsn string, pemToken string, tableName string) (
	uuidUser string,
	apiTokenResult string,
	webhookPath string,
	exists bool,
	err error) {

	// 1. 标准化输入PEM格式
	normalizedPEM := strings.ReplaceAll(pemToken, "\r\n", "\n")
	normalizedPEM = strings.TrimSpace(normalizedPEM)

	// 调试：打印标准化的PEM
	fmt.Printf("[DEBUG] 标准化后的PEM: \n%s\n", normalizedPEM)

	// 2. 将PEM转换为DER二进制
	derBytes, err := pemToDER(normalizedPEM)
	if err != nil {
		return "", "", "", false, fmt.Errorf("PEM转换失败: %w", err)
	}

	// 调试：打印DER字节长度
	fmt.Printf("[DEBUG] DER二进制长度: %d 字节\n", len(derBytes))

	// 3. 将DER二进制转换为Base64字符串
	derBase64 := base64.StdEncoding.EncodeToString(derBytes)

	// 添加您要求的调试打印 - 重要！
	fmt.Printf("<der_str64>%s</der_str64>\n", derBase64)

	// 4. 建立数据库连接
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return "", "", "", false, fmt.Errorf("数据库连接配置错误: %w", err)
	}
	defer db.Close()

	// 5. 验证数据库连通性
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		return "", "", "", false, fmt.Errorf("数据库连接失败: %w", err)
	}

	// 6. 执行参数化查询（比较Base64编码的DER）
	query := fmt.Sprintf(`
	SELECT 
		uuid_user,
		api_token,  -- 数据库中存储的是Base64编码的DER
		webhook_path
	FROM %s
	WHERE api_token = ?
	LIMIT 2`, tableName)

	// 调试：打印执行的SQL
	fmt.Printf("[DEBUG] 执行查询: %s\n参数: %s\n", query, derBase64)

	rows, err := db.QueryContext(ctx, query, derBase64)
	if err != nil {
		return "", "", "", false, fmt.Errorf("查询执行失败: %w", err)
	}
	defer rows.Close()

	// 7. 处理查询结果
	var resultCount int
	for rows.Next() {
		if resultCount >= 1 {
			return "", "", "", false, errors.New("发现重复的 API Token 记录")
		}

		var (
			rawUUID       string
			dbTokenBase64 string // 数据库中存储的Base64编码的DER
		)
		if err := rows.Scan(&rawUUID, &dbTokenBase64, &webhookPath); err != nil {
			return "", "", "", false, fmt.Errorf("数据解析失败: %w", err)
		}

		// 调试：打印数据库中的Base64 DER
		fmt.Printf("[DEBUG] 数据库中的DER Base64: %s\n", dbTokenBase64)

		// 8. 将数据库中的Base64 DER转回PEM格式返回
		if dbDerBytes, err := base64.StdEncoding.DecodeString(dbTokenBase64); err == nil {
			apiTokenResult = derToPEM(dbDerBytes)
			// 调试：打印转换后的PEM
			fmt.Printf("[DEBUG] 转换回PEM格式: \n%s\n", apiTokenResult)
		} else {
			apiTokenResult = "" // 如果解码失败，返回空
			fmt.Printf("[WARN] Base64解码失败: %v\n", err)
		}

		// 9. 验证UUID格式
		if _, err := uuid.Parse(rawUUID); err != nil {
			return "", "", "", false, fmt.Errorf("无效的 UUID 格式: %s", rawUUID)
		}

		uuidUser = rawUUID
		resultCount++
	}

	// 10. 结果处理
	if err := rows.Err(); err != nil {
		return "", "", "", false, fmt.Errorf("结果集错误: %w", err)
	}

	switch resultCount {
	case 0:
		fmt.Printf("[INFO] 未找到匹配记录\n")
		return "", "", "", false, nil
	case 1:
		fmt.Printf("[INFO] 找到匹配记录: UUID=%s\n", uuidUser)
		return uuidUser, apiTokenResult, webhookPath, true, nil
	default:
		fmt.Printf("[ERROR] 发现多条重复记录\n")
		return "", "", "", false, errors.New("发现多条重复记录")
	}
}

// PEM转DER辅助函数
func pemToDER(pemData string) ([]byte, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, errors.New("PEM解码失败")
	}
	return block.Bytes, nil
}

// DER转PEM辅助函数
func derToPEM(derData []byte) string {
	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: derData,
	}
	return string(pem.EncodeToMemory(block))
}
func insertAuthRecord(
	dsn string,
	uuidStr string,
	apiToken string,
	webhookPath string,
	tableName string,
) error {
	// 验证表名合法性
	if tableName != "visitors" && tableName != "admins" {
		return fmt.Errorf("禁止操作非认证表: %s", tableName)
	}

	// 验证UUID格式
	if _, err := uuid.Parse(uuidStr); err != nil {
		return fmt.Errorf("无效的UUID格式: %s", uuidStr)
	}

	// 创建带超时的上下文
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// 建立数据库连接
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return fmt.Errorf("连接配置错误: %w", err)
	}
	defer db.Close()

	// 验证数据库连通性
	if err := db.PingContext(ctx); err != nil {
		return fmt.Errorf("数据库连接失败: %w", err)
	}

	// 构建动态SQL语句（参数化处理值）
	query := fmt.Sprintf(`
        INSERT INTO %s 
            (uuid_user, api_token, webhook_path)
        VALUES
            (?, ?, ?)
    `, tableName)

	// 执行插入操作
	result, err := db.ExecContext(ctx, query, uuidStr, apiToken, webhookPath)
	if err != nil {
		return fmt.Errorf("插入失败: %w", err)
	}

	// 验证影响行数
	if rowsAffected, _ := result.RowsAffected(); rowsAffected != 1 {
		return fmt.Errorf("异常插入结果，影响行数: %d", rowsAffected)
	}

	return nil
}
func generateKeyPair(pemKeyStr string) (string, string, error) {
	var privateKey *rsa.PrivateKey
	var err error

	// 生成或解析私钥
	if pemKeyStr == "" {
		// 生成 4096 位 RSA 私钥
		privateKey, err = rsa.GenerateKey(rand.Reader, 4096)
		if err != nil {
			return "", "", fmt.Errorf("密钥生成失败: %w", err)
		}
	} else {
		// 解析现有私钥
		block, _ := pem.Decode([]byte(pemKeyStr))
		if block == nil {
			return "", "", errors.New("无效的PEM格式")
		}

		// 支持 PKCS#8 和 PKCS#1 格式
		switch block.Type {
		case "PRIVATE KEY": // PKCS#8
			parsedKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return "", "", fmt.Errorf("私钥解析失败: %w", err)
			}
			privateKey = parsedKey.(*rsa.PrivateKey)
		case "RSA PRIVATE KEY": // PKCS#1
			privateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
			if err != nil {
				return "", "", fmt.Errorf("私钥解析失败: %w", err)
			}
		default:
			return "", "", fmt.Errorf("不支持的PEM类型: %s", block.Type)
		}
	}

	// 生成公钥
	publicKey := &privateKey.PublicKey

	// 编码私钥 (PKCS#8)
	privateBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return "", "", fmt.Errorf("私钥编码失败: %w", err)
	}

	privateBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateBytes,
	}
	privatePEM := string(pem.EncodeToMemory(privateBlock))

	// 编码公钥 (PKIX)
	publicBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", "", fmt.Errorf("公钥编码失败: %w", err)
	}

	publicBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicBytes,
	}
	publicPEM := string(pem.EncodeToMemory(publicBlock))

	return privatePEM, publicPEM, nil
}
func isTimestampValid(timeStampStr string) (bool, error) {
	// 记录客户端时间戳
	fmt.Printf("[DEBUG] 客户端时间戳: %s\n", timeStampStr)

	timestamp, err := strconv.ParseInt(timeStampStr, 10, 64)
	if err != nil {
		fmt.Printf("[ERROR] 时间戳格式错误: %v\n", err)
		return false, fmt.Errorf("时间戳格式错误: %v (需要十进制数字)", err)
	}

	targetTime := time.Unix(timestamp, 0).UTC()
	now := time.Now().UTC()
	timeDiff := now.Sub(targetTime).Abs()

	// 打印详细时间信息
	fmt.Printf("[DEBUG] 服务端当前UTC时间: %s\n", now.Format(time.RFC3339))
	fmt.Printf("[DEBUG] 客户端时间戳转换后: %s\n", targetTime.Format(time.RFC3339))
	fmt.Printf("[DEBUG] 时间差: %.2f 秒\n", timeDiff.Seconds())

	const allowedRange = 10 * time.Minute
	if timeDiff <= allowedRange {
		fmt.Println("[DEBUG] 时间戳有效")
		return true, nil
	}

	fmt.Printf("[WARN] 时间戳超时 (允许范围: ±%.0f 分钟)\n", allowedRange.Minutes())
	return false, nil
}
func generatePID() (string, uint) {
	// 初始化随机种子
	source := mrand.NewSource(time.Now().UnixNano())
	r := mrand.New(source)

	// 定义现代系统常见的 PID 范围 (1 ~ 4194304)
	min := 1
	max := 4194304 // 对应 /proc/sys/kernel/pid_max 的典型最大值

	// 生成随机 PID
	pidNum := uint(r.Intn(max-min+1) + min)

	// 转换为字符串
	pidStr := strconv.FormatUint(uint64(pidNum), 10)

	return pidStr, pidNum
}
func jSONToMap(jsonStr string) (map[string]string, error) {
	// 1. 解析为通用map结构
	var rawMap map[string]interface{}
	if err := json.Unmarshal([]byte(jsonStr), &rawMap); err != nil {
		return nil, fmt.Errorf("JSON解析失败: %v", err)
	}

	// 2. 创建结果map并转换值
	result := make(map[string]string)
	for key, value := range rawMap {
		strValue, err := convertToString(value)
		if err != nil {
			return nil, fmt.Errorf("键[%s]转换失败: %v", key, err)
		}
		result[key] = strValue
	}

	return result, nil
}

// 递归转换值为字符串 (处理嵌套结构)
func convertToString(v interface{}) (string, error) {
	switch val := v.(type) {
	case string:
		return val, nil
	case float64: // JSON数字默认解析为float64
		return fmt.Sprintf("%v", val), nil
	case bool:
		return fmt.Sprintf("%t", val), nil
	case nil:
		return "", nil
	case map[string]interface{}: // 嵌套对象
		return "", fmt.Errorf("不支持嵌套对象")
	case []interface{}: // 数组
		return "", fmt.Errorf("不支持数组类型")
	default:
		return "", fmt.Errorf("无法识别的类型: %s", reflect.TypeOf(v))
	}
}
func getSHA256HashCode(stringMessage string) string {

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
func vftoken(v10, dsn string) (string, string, bool, error) {
	fmt.Println("req.Var10是: ", v10)
	decodedCert, err := base64.StdEncoding.DecodeString(v10)
	if err != nil {
		log.Printf("证书解码失败：%v", err)
		return "", "", false, err
	}

	// 二次PEM格式验证
	if block, _ := pem.Decode(decodedCert); block == nil {
		log.Printf("无效的PEM结构")
		return "", "", false, nil
	}

	stmmp_pid, cer_get, if_match_pem, err := cd59.VerifyAndExtractSubjectFromPEM(string(decodedCert))
	if err != nil {
		fmt.Println(err)
		return "", "", false, err
	}
	fmt.Println("stmmp是: ", stmmp_pid)
	fmt.Println("cer_get是: ", cer_get)
	str1, str2, str3, if_searched, err := queryVisitorByAPIToken(dsn, cer_get, "visitors")
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("搜索数据库中保存api-token", str1, str2, str3)
	if !if_searched || !if_match_pem {
		if !if_searched {
			fmt.Println("没有找到token!")
		}
		return "", "", false, nil
	}
	return stmmp_pid, cer_get, true, nil
}

// 新增函数：插入设备隶属关系到 endpoint_devices_list
func insertDeviceRelation(dsn string, userUUID string, deviceUUID string) error {
	// 建立数据库连接
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return fmt.Errorf("数据库连接失败: %v", err)
	}
	defer db.Close()

	// 准备插入语句（使用UUID类型需要确保数据库驱动支持）
	query := `
        INSERT INTO endpoint_devices_list 
            (device_holder_ID_card_UUID, device_UUID) 
        VALUES (?, ?)
        ON DUPLICATE KEY UPDATE device_UUID=VALUES(device_UUID)`

	// 执行插入操作
	_, err = db.Exec(query, userUUID, deviceUUID)
	if err != nil {
		return fmt.Errorf("插入设备关系失败: %v", err)
	}

	return nil
}

// 方式1：直接复用现有的queryVisitorByAPIToken函数
func GetWebhookByCGT(dsn string, cgt string) (string, error) {
	// 查询visitors表，第三个参数指定表名
	_, _, webhook, exists, err := queryVisitorByAPIToken(dsn, cgt, "visitors")
	if err != nil {
		return "", fmt.Errorf("数据库查询失败: %w", err)
	}
	if !exists {
		return "", fmt.Errorf("未找到匹配的公钥记录")
	}
	return webhook, nil
}

// 方式2：独立实现专用查询函数（带上下文超时控制）
func QueryWebhookByPublicKey(ctx context.Context, dsn string, publicKey string) (string, error) {
	// 建立带超时的上下文
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	// 建立数据库连接
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return "", fmt.Errorf("数据库连接失败: %w", err)
	}
	defer db.Close()

	// 参数化查询防止SQL注入
	query := `
        SELECT webhook_path 
        FROM visitors 
        WHERE api_token = ?
        LIMIT 1`

	var webhook string
	err = db.QueryRowContext(ctx, query, publicKey).Scan(&webhook)

	switch {
	case err == sql.ErrNoRows:
		return "", fmt.Errorf("公钥不存在")
	case err != nil:
		return "", fmt.Errorf("查询执行失败: %w", err)
	default:
		return webhook, nil
	}
}
func SendToWebhook(webhookURL string, message string, timeout time.Duration) (int, error) {
	// 1. 构建JSON数据
	payload := map[string]string{
		"message": message, // 固定字段名，值传入任意字符串
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return 0, fmt.Errorf("JSON编码失败: %w", err)
	}

	// 2. 创建带超时的context
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// 3. 创建HTTP请求
	req, err := http.NewRequestWithContext(ctx, "POST", webhookURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return 0, fmt.Errorf("创建请求失败: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "WebhookSender/1.0")

	// 4. 发送请求
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("请求发送失败: %w", err)
	}
	defer resp.Body.Close()

	// 5. 验证响应状态码
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return resp.StatusCode, fmt.Errorf("非成功状态码: %d", resp.StatusCode)
	}

	return resp.StatusCode, nil
}
func Dedim_Map(mymap map[string]string) string {
	jsonData, err := json.Marshal(mymap)
	if err != nil {
		log.Printf("JSON序列化失败: %v", err)
		return ""
	}
	return base64.StdEncoding.EncodeToString(jsonData)
}

func Dimming_Map(encoded string) map[string]string {
	if encoded == "" {
		return make(map[string]string)
	}

	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		log.Printf("Base64解码失败: %v", err)
		return make(map[string]string)
	}

	var result map[string]string
	if err := json.Unmarshal(decoded, &result); err != nil {
		log.Printf("JSON反序列化失败: %v", err)
		return make(map[string]string)
	}

	return result
}
func Encode_to_B64(for_encode string) string {
	var str = for_encode
	strbytes := []byte(str)
	encoded := base64.StdEncoding.EncodeToString(strbytes)
	return encoded
}
func DecodeB64(message string) string {
	/*base64Text := make([]byte, base64.StdEncoding.DecodedLen(len(message)))
	base64.StdEncoding.Decode(base64Text, []byte(message))
	fmt.Printf("base64: %s\n", base64Text)
	return string(base64Text)*/
	decoded, err := base64.StdEncoding.DecodeString(message)
	retour := string(decoded)
	if err != nil {
		log.Fatal("db64_err: ", err)
	}
	return retour
}

type HTTPService struct {
	data           map[string]string
	taskPool       *string
	lifeCycleOrder *string
	dataLock       sync.RWMutex
	globalLock     *sync.RWMutex
	config         *ServerConfig // 添加config字段
	server         *http.Server  // 添加 server 字段
}

// NewHTTPService 创建HTTP服务实例
// 输入参数：initialData - 初始化数据
// 返回值：*HTTPService实例
func NewHTTPService(
	initialData map[string]string,
	taskPool *string,
	lifeCycleOrder *string,
	globalLock *sync.RWMutex,
	config *ServerConfig, // 新增配置参数
) *HTTPService {
	copyData := make(map[string]string, len(initialData))
	for k, v := range initialData {
		copyData[k] = v
	}

	return &HTTPService{
		data:           copyData,
		taskPool:       taskPool,
		lifeCycleOrder: lifeCycleOrder,
		globalLock:     globalLock,
		config:         config, // 保存配置
	}
}

// Start 启动HTTP服务
// 输入参数：port - 监听端口号
// 返回值：error - 启动错误
func (s *HTTPService) Start(port string) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/task/", s.rateLimit(s.taskHandler))
	// 配置路由
	//mux := http.NewServeMux()
	mux.HandleFunc("/", s.dataHandler)
	//mux.HandleFunc("/update", s.updateHandler)
	//mux.HandleFunc("/task/", s.taskHandler) // 新增路由

	s.server = &http.Server{
		Addr:    ":" + port,
		Handler: mux,
	}

	// 启动服务
	return s.server.ListenAndServe()
}

// 数据展示处理器
func (s *HTTPService) dataHandler(w http.ResponseWriter, r *http.Request) {
	s.dataLock.RLock()         // 替换 s.mutex
	defer s.dataLock.RUnlock() // 替换 s.mutex

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s.data)
}

// 数据更新处理器
func (s *HTTPService) updateHandler(w http.ResponseWriter, r *http.Request) {
	s.dataLock.RLock()         // 替换 s.mutex
	defer s.dataLock.RUnlock() // 替换 s.mutex

	// 解析请求参数
	query := r.URL.Query()
	key := query.Get("key")
	value := query.Get("value")

	if key == "" || value == "" {
		http.Error(w, "Missing parameters", http.StatusBadRequest)
		return
	}

	// 更新数据
	s.data[key] = value
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "updated",
		"updated": key,
	})
}
func (s *HTTPService) taskHandler(w http.ResponseWriter, r *http.Request) {
	// 只接受POST请求
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 提取PID并验证
	pathSegments := strings.Split(r.URL.Path, "/")
	if len(pathSegments) < 3 {
		http.Error(w, "Invalid path format", http.StatusBadRequest)
		return
	}
	pid := pathSegments[2]
	if pid == "" {
		http.Error(w, "Missing PID parameter", http.StatusBadRequest)
		return
	}

	// 解析请求体
	var requestBody struct {
		IDCard string `json:"id_card"`
	}
	if err := json.NewDecoder(r.Body).Decode(&requestBody); err != nil {
		http.Error(w, "Invalid JSON format", http.StatusBadRequest)
		return
	}
	if requestBody.IDCard == "" {
		http.Error(w, "Missing id_card parameter", http.StatusBadRequest)
		return
	}

	// 对PID进行Base64编码
	encodedPID := Encode_to_B64(pid)

	// 获取锁（保护数据访问）
	s.dataLock.RLock()
	defer s.dataLock.RUnlock()
	s.globalLock.RLock()
	defer s.globalLock.RUnlock()

	// 复制全局状态
	taskPool := *s.taskPool
	lifeCycleOrder := *s.lifeCycleOrder

	// 解码任务池和生命周期
	taskMap := Dimming_Map(taskPool)
	lifecycleMap := Dimming_Map(lifeCycleOrder)

	// 使用编码后的PID查询
	taskValue := DecodeB64(taskMap[encodedPID])
	lifecycleTS := DecodeB64(lifecycleMap[encodedPID])

	// 处理未找到PID的情况
	if taskValue == "" {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "PID not found in task pool",
		})
		return
	}

	// 根据身份证号生成设备持有者UUID（与注册时一致）
	hmacBytes, _, err := generateIDHMAC(s.config.HMACKey, requestBody.IDCard)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	generatedUserUUID := uugen.Byte_in_UU(hmacBytes)

	// 比较生成的UUID与任务值
	matched := generatedUserUUID == taskValue

	// 构建响应
	response := struct {
		Matched           bool   `json:"matched"`
		TaskValue         string `json:"task_value"`
		LifecycleTS       string `json:"lifecycle_timestamp"`
		CurrentTime       string `json:"current_time"`
		GeneratedUserUUID string `json:"generated_user_uuid"`
	}{
		Matched:           matched,
		TaskValue:         taskValue,
		LifecycleTS:       lifecycleTS,
		CurrentTime:       time.Now().UTC().Format(time.RFC3339),
		GeneratedUserUUID: generatedUserUUID,
	}

	// 返回响应
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("JSON编码失败: %v", err)
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
	}
}
func isValidPID(pid string) bool {
	if len(pid) > 100 { // 根据实际需要调整长度限制
		return false
	}
	// 添加更复杂的验证逻辑
	return true
}
func (s *HTTPService) rateLimit(next http.HandlerFunc) http.HandlerFunc {
	type visitor struct {
		limiter  *rate.Limiter
		lastSeen time.Time
	}
	var (
		visitors = make(map[string]*visitor)
		mu       sync.Mutex
	)

	// 清理旧IP的goroutine
	go func() {
		for {
			time.Sleep(time.Minute)
			mu.Lock()
			for ip, v := range visitors {
				if time.Since(v.lastSeen) > 3*time.Minute {
					delete(visitors, ip)
				}
			}
			mu.Unlock()
		}
	}()

	return func(w http.ResponseWriter, r *http.Request) {
		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		mu.Lock()
		v, exists := visitors[ip]
		if !exists {
			// 每秒最多5个请求，令牌桶容量5
			v = &visitor{limiter: rate.NewLimiter(1, 5)}
			visitors[ip] = v
		}
		v.lastSeen = time.Now()
		mu.Unlock()

		if !v.limiter.Allow() {
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}

		next(w, r)
	}
}

func GetHolderUUIDByDeviceUUID(dsn string, deviceUUID string) (string, error) {
	// 建立数据库连接
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return "", fmt.Errorf("数据库连接失败: %v", err)
	}
	defer db.Close()

	// 直接查询持有者UUID
	var holderUUID string
	err = db.QueryRow(`
        SELECT device_holder_ID_card_UUID 
        FROM endpoint_devices_list 
        WHERE device_UUID = ?`, deviceUUID).Scan(&holderUUID)

	if err != nil {
		if err == sql.ErrNoRows {
			return "", fmt.Errorf("未找到设备持有者记录")
		}
		return "", fmt.Errorf("查询设备持有者失败: %v", err)
	}

	return holderUUID, nil
}
