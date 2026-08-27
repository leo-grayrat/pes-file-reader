# 第三方源码说明（third_party/pesXdecrypter）

本目录源码来源于 GitHub 开源项目：

- 仓库：https://github.com/the4chancup/pesXdecrypter
- 描述：Pro Evolution Soccer 2016-2020 存档加解密（含 PES2021 主密钥）
- 许可：
  - `crypt.c/h`、`masterkey.c/h`、`decrypter.c`、`encrypter.c` —— public domain (unlicense)
  - `mt19937ar.c/h` —— Takuji Nishimura & Makoto Matsumoto 的 MT19937 实现，BSD-3 许可（详见文件头注释）

## 本地编译适配改动（均不影响算法逻辑）

1. `masterkey.h` 的 `MasterKeyZero` 补 `extern`（修复多编译单元链接期重复定义）。
2. `masterkey.h` 补充 `MasterKeyPes21` 的 extern 声明（原头文件漏声明）。
3. `crypt.c` 的 `writeFileDir` 改用 Windows API `GetFileAttributesA`/`CreateDirectoryA` 判断与创建目录（解决 MinGW 下 `stat`/`mkdir` 对反斜杠路径失效的可移植性问题）。

## 编译（PES2021 版，需 MinGW gcc + -DUSE_PES21_MASTER_KEY）

```
gcc -DUSE_PES21_MASTER_KEY -O2 -o decrypter.exe src/crypt.c src/masterkey.c src/mt19937ar.c src/decrypter.c
gcc -DUSE_PES21_MASTER_KEY -O2 -o encrypter.exe src/crypt.c src/masterkey.c src/mt19937ar.c src/encrypter.c
```

## 用法

```
decrypter.exe 输入存档文件 输出目录
encrypter.exe 输入目录 输出存档文件
```

解密后输出目录包含 6 个块：`encryptHeader.dat`、`header.dat`、`description.dat`、`logo.png`、`data.dat`、`version.txt`，其中 `data.dat` 是明文存档主体。