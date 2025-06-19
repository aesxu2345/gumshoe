// idconvetor/go.mod
module idconvetor

go 1.23

require golang.org/x/crypto v0.37.0 // 保持版本但通过replace覆盖

replace golang.org/x/crypto => ./bcrypt

// Copyright 2025 YU HENG LU (aesxu2345@outlook.com)
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// See the LICENSE file for full terms.