module gumshoe

go 1.23.5

require (
	github.com/go-sql-driver/mysql v1.9.2
	google.golang.org/grpc v1.72.0
	google.golang.org/protobuf v1.36.6
	gumshoe/teesign v0.0.0
)

require (
	filippo.io/edwards25519 v1.1.0 // indirect
	github.com/Lyafei/go-rsa v0.0.0-20200519074919-6694e0e47bb8 // indirect
	github.com/golang-infrastructure/go-try-catch v0.0.1 // indirect
	golang.org/x/crypto v0.37.0 // indirect
	golang.org/x/net v0.39.0 // indirect
	golang.org/x/sys v0.32.0 // indirect
	golang.org/x/text v0.24.0 // indirect
	golang.org/x/time v0.11.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20250428153025-10db94c68c34 // indirect
)

require (
	github.com/ulikunitz/xz v0.5.12
	idconvetor v0.0.0
)

require (
	cd59 v0.0.0
	github.com/google/uuid v1.6.0
	github.com/spf13/pflag v1.0.6
)

require uugen v0.0.0

replace uugen => ./uugen

replace (
	golang.org/x/crypto => ./idconvetor/bcrypt // 指向主项目的替换路径
	gumshoe/teesign => ./teesign
	idconvetor => ./idconvetor
)

replace cd59 => ./cd59

require sigdifictor v0.0.0

replace sigdifictor => ./sigdifictor

require lzmaquery v0.0.0

replace lzmaquery => ./lzmaquery

// Copyright 2025 YU HENG LU (aesxu2345@outlook.com)
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// See the LICENSE file for full terms.