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

package lzmaquery

import (
	"bytes"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/ulikunitz/xz/lzma"
)

func HandleDeviceDetails(dsn string, deviceUUID string, deviceTEEKey, smbiosHash, hhdHash, gpuHash, ensMacHash string) (bool, error) {
	fmt.Printf("等待插入的是:\n%s\n%s\n%s\n%s\n%s", deviceTEEKey, smbiosHash, hhdHash, gpuHash, ensMacHash)
	if deviceUUID == "" {
		return false, errors.New("deviceUUID cannot be empty")
	}

	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return false, err
	}
	defer db.Close()

	// Check if device exists, insert if not
	var exists bool
	err = db.QueryRow("SELECT EXISTS(SELECT 1 FROM device_general_details WHERE device_UUID = ?)", deviceUUID).Scan(&exists)
	if err != nil {
		return false, err
	}
	if !exists {
		_, err = db.Exec("INSERT INTO device_general_details (device_UUID) VALUES (?)", deviceUUID)
		if err != nil {
			return false, err
		}
	}

	fields := []struct {
		value  string
		column string
	}{
		{deviceTEEKey, "device_TEE_key"},
		{smbiosHash, "SMIBIOS_hash"},
		{hhdHash, "HHD_Hash"},
		{gpuHash, "GPU_Hash"},
		{ensMacHash, "ens_mac_Hash"},
	}

	for _, field := range fields {
		if field.value == "" {
			continue
		}

		var currentBlob []byte
		err := db.QueryRow(fmt.Sprintf("SELECT %s FROM device_general_details WHERE device_UUID = ?", field.column), deviceUUID).Scan(&currentBlob)
		if err != nil && err != sql.ErrNoRows {
			return false, err
		}

		newBase64 := base64.StdEncoding.EncodeToString([]byte(field.value))
		var decompressed []byte

		if len(currentBlob) > 0 {
			decompressed, err = lzmaDecompress(currentBlob)
			if err != nil {
				return false, err
			}
		}

		var newContent string
		if len(decompressed) == 0 {
			newContent = newBase64 + "\n"
		} else {
			existingContent := strings.TrimRight(string(decompressed), "\n")
			newContent = existingContent + "\n" + newBase64 + "\n"
		}

		compressed, err := lzmaCompress([]byte(newContent))
		if err != nil {
			return false, err
		}

		_, err = db.Exec(fmt.Sprintf("UPDATE device_general_details SET %s = ? WHERE device_UUID = ?", field.column), compressed, deviceUUID)
		if err != nil {
			return false, err
		}
	}

	return true, nil
}

func QueryDevicesByHashes(dsn string, deviceTEEKey, smbiosHash, hhdHash, gpuHash, ensMacHash string) (string, error) {
	fmt.Printf("等待查询的是:\n%s\n%s\n%s\n%s\n%s", deviceTEEKey, smbiosHash, hhdHash, gpuHash, ensMacHash)
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return "", err
	}
	defer db.Close()

	queries := []struct {
		value  string
		column string
	}{
		{deviceTEEKey, "device_TEE_key"},
		{smbiosHash, "SMIBIOS_hash"},
		{hhdHash, "HHD_Hash"},
		{gpuHash, "GPU_Hash"},
		{ensMacHash, "ens_mac_Hash"},
	}

	uuidSet := make(map[string]struct{})
	for _, q := range queries {
		if q.value == "" {
			continue
		}

		valueBase64 := base64.StdEncoding.EncodeToString([]byte(q.value))

		rows, err := db.Query(fmt.Sprintf("SELECT device_UUID, %s FROM device_general_details WHERE %s IS NOT NULL", q.column, q.column))
		if err != nil {
			return "", err
		}
		defer rows.Close()

		for rows.Next() {
			var deviceUUID string
			var blobData []byte
			if err := rows.Scan(&deviceUUID, &blobData); err != nil {
				return "", err
			}

			decompressed, err := lzmaDecompress(blobData)
			if err != nil {
				return "", err
			}

			if strings.Contains(string(decompressed), valueBase64) {
				uuidSet[deviceUUID] = struct{}{}
			}
		}
		if err := rows.Err(); err != nil {
			return "", err
		}
	}

	uuids := make([]string, 0, len(uuidSet))
	for u := range uuidSet {
		uuids = append(uuids, u)
	}

	result := strings.Join(uuids, ",")

	switch len(uuids) {
	case 0:
		return "", nil
	case 1:
		return result, nil
	default:
		return result, fmt.Errorf("multiple devices matched: %s", result)
	}
}

func lzmaCompress(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	writer, err := lzma.NewWriter(&buf)
	if err != nil {
		return nil, err
	}
	if _, err := writer.Write(data); err != nil {
		return nil, err
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func lzmaDecompress(data []byte) ([]byte, error) {
	reader, err := lzma.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	return io.ReadAll(reader)
}
