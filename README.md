# FileCryptorator

Password-based AES-256-GCM file encryption for Windows PowerShell 5.1 and later.

This is a testing and learning tool. It is not a substitute for BitLocker, age, or gpg. Malicious use is prohibited.

## What changed

The old script used AES-CBC and `SHA256(password)` with no integrity check. That format is **not** compatible with this version. Re-encrypt anything you still have the plaintext for.

## Quick start

```powershell
Set-Location C:\path\to\FileCryptorator
Set-ExecutionPolicy -Scope Process Bypass

# Interactive menu + file picker
.\FileCrypter.ps1

# Encrypt / decrypt
$pw = Read-Host 'Password' -AsSecureString
.\FileCrypter.ps1 -Encrypt -Path .\budget.xlsx -Password $pw
.\FileCrypter.ps1 -Decrypt -Path .\budget.xlsx.fcrypt -Password $pw

# Extension picks the mode if you omit -Encrypt / -Decrypt
.\FileCrypter.ps1 -Path .\budget.xlsx.fcrypt -Password $pw

# Isolated crypto check
.\FileCrypter.ps1 -SelfTest
```

The original file is never deleted. Encrypt writes `filename.ext.fcrypt` next to the source unless you pass `-Destination`.

## Options

| Parameter | Purpose |
| --- | --- |
| `-Encrypt` / `-Decrypt` | Mode. Optional if the path ends in `.fcrypt` (decrypt) or not (encrypt). |
| `-Path` | One or more files. Also accepts pipeline input. |
| `-Destination` | Output file, or a folder to write into. |
| `-Password` | `SecureString`. Prompted if omitted. Encrypt asks twice. |
| `-Iterations` | PBKDF2 rounds for new files (default 600000). Stored in the file header. |
| `-Force` | Overwrite an existing output file. |
| `-SelfTest` | Round-trip, empty file, wrong password, tamper, and overwrite checks. |

## File format

```
FCR1          4 bytes ASCII
version       1 byte  (1)
kdf           1 byte  (1 = PBKDF2-SHA256)
iterations    4 bytes uint32 little-endian
salt          16 bytes
nonce         12 bytes
tag           16 bytes
ciphertext    remainder
```

The header through the nonce is GCM additional authenticated data. A flipped bit or a wrong password fails instead of writing garbage.

AES-GCM comes from Windows CNG (`bcrypt`), so this runs on Windows PowerShell 5.1 where `AesGcm` is not in .NET Framework.

The file is loaded into memory. Fine for documents and typical attachments; not aimed at multi-gigabyte files.

## Author

[@cyberw01f](https://github.com/cyb3rw01f)
