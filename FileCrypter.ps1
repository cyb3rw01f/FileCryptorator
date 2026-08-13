#Requires -Version 5.1
<#
.SYNOPSIS
Encrypt or decrypt a file with a password using AES-256-GCM.

.DESCRIPTION
Password-based file encryption for a single file or a list of files.
Keys are derived with PBKDF2-SHA256 (salted, iterated). Payload is AES-256-GCM,
so a flipped bit or a wrong password fails closed instead of writing garbage.

Default output is next to the source file:
  encrypt  report.pdf        -> report.pdf.fcrypt
  decrypt  report.pdf.fcrypt -> report.pdf

The original file is never deleted. Older FileCryptorator files (raw AES-CBC,
no header) cannot be opened by this version.

.PARAMETER Encrypt
Encrypt the file(s) at -Path. Implied when -Path does not end in .fcrypt.

.PARAMETER Decrypt
Decrypt the file(s) at -Path. Implied when -Path ends in .fcrypt.

.PARAMETER Path
File to encrypt or decrypt. Accepts a list and pipeline input (FullName).

.PARAMETER Destination
Output file, or a folder to write into. Defaults to next to the source.

.PARAMETER Password
SecureString password. If omitted, you are prompted. Encrypt prompts twice.

.PARAMETER Iterations
PBKDF2 iteration count written into new files. Default 600000.
Existing files use the count stored in their header.

.PARAMETER Force
Overwrite an existing output file.

.PARAMETER SelfTest
Run an isolated round-trip and tamper check, then exit.

.EXAMPLE
.\FileCrypter.ps1

.EXAMPLE
$pw = Read-Host 'Password' -AsSecureString
.\FileCrypter.ps1 -Encrypt -Path .\budget.xlsx -Password $pw

.EXAMPLE
.\FileCrypter.ps1 -Decrypt -Path .\budget.xlsx.fcrypt -Destination .\restored.xlsx

.EXAMPLE
Get-ChildItem .\*.pdf | .\FileCrypter.ps1 -Encrypt

.EXAMPLE
.\FileCrypter.ps1 -SelfTest

.NOTES
File layout (version 1):
  FCR1          4 bytes ASCII
  version       1 byte  (1)
  kdf           1 byte  (1 = PBKDF2-SHA256)
  iterations    4 bytes uint32 little-endian
  salt          16 bytes
  nonce         12 bytes
  tag           16 bytes
  ciphertext    remainder

AAD binds the header through the nonce. AES-GCM is provided by Windows CNG
so this runs on Windows PowerShell 5.1 as well as PowerShell 7.

Author @cyberw01f
#>
[CmdletBinding(DefaultParameterSetName = 'Interactive')]
param(
    [Parameter(Mandatory = $true, ParameterSetName = 'Encrypt')]
    [switch]$Encrypt,

    [Parameter(Mandatory = $true, ParameterSetName = 'Decrypt')]
    [switch]$Decrypt,

    [Parameter(Mandatory = $true, ParameterSetName = 'SelfTest')]
    [switch]$SelfTest,

    [Parameter(Mandatory = $true, ParameterSetName = 'Encrypt', Position = 0, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
    [Parameter(Mandatory = $true, ParameterSetName = 'Decrypt', Position = 0, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
    [Parameter(Mandatory = $true, ParameterSetName = 'Auto', Position = 0, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
    [Alias('FullName', 'LiteralPath', 'PSPath')]
    [string[]]$Path,

    [Parameter(ParameterSetName = 'Encrypt')]
    [Parameter(ParameterSetName = 'Decrypt')]
    [Parameter(ParameterSetName = 'Auto')]
    [Parameter(ParameterSetName = 'Interactive')]
    [string]$Destination,

    [Parameter(ParameterSetName = 'Encrypt')]
    [Parameter(ParameterSetName = 'Decrypt')]
    [Parameter(ParameterSetName = 'Auto')]
    [Parameter(ParameterSetName = 'Interactive')]
    [SecureString]$Password,

    [Parameter(ParameterSetName = 'Encrypt')]
    [Parameter(ParameterSetName = 'Auto')]
    [Parameter(ParameterSetName = 'Interactive')]
    [ValidateRange(100000, 10000000)]
    [int]$Iterations = 600000,

    [Parameter(ParameterSetName = 'Encrypt')]
    [Parameter(ParameterSetName = 'Decrypt')]
    [Parameter(ParameterSetName = 'Auto')]
    [Parameter(ParameterSetName = 'Interactive')]
    [switch]$Force
)

begin {
function Initialize-FileCryptoratorDefaults {
    $script:FcExtension = '.fcrypt'
    $script:FcMagicText = 'FCR1'
    $script:FcVersion = [byte]1
    $script:FcKdfPbkdf2Sha256 = [byte]1
    $script:FcSaltSize = 16
    $script:FcNonceSize = 12
    $script:FcTagSize = 16
    $script:FcMinIterations = 100000
    $script:FcMaxIterations = 10000000
    $script:FcHeaderSize = 54
    $script:FcMemoryWarnBytes = 100MB

    $script:FcLogo = @'
	=================================================================
			   _                         ___  _  __
		 ___ _   _| |__   ___ _ ____      __/ _ \/ |/ _|
		/ __| | | | '_ \ / _ \ '__\ \ /\ / / | | | | |_
	       | (__| |_| | |_) |  __/ |   \ V  V /| |_| | |  _|
		\___|\__, |_.__/ \___|_|    \_/\_/  \___/|_|_|
		      |___/

	==================================================================
			     @cyberw01f
			  FileCryptorator
'@
}

function Initialize-FileCryptoratorCrypto {
    if ('FileCryptorator.AesGcmCrypto' -as [type]) {
        return
    }

    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Text;

namespace FileCryptorator
{
    public static class AesGcmCrypto
    {
        public const int NonceSize = 12;
        public const int TagSize = 16;

        public static void Encrypt(byte[] key, byte[] nonce, byte[] plaintext, byte[] ciphertext, byte[] tag, byte[] aad)
        {
            Transform(key, nonce, plaintext, ciphertext, tag, aad, true);
        }

        public static void Decrypt(byte[] key, byte[] nonce, byte[] ciphertext, byte[] tag, byte[] plaintext, byte[] aad)
        {
            Transform(key, nonce, ciphertext, plaintext, tag, aad, false);
        }

        private static void Transform(byte[] key, byte[] nonce, byte[] input, byte[] output, byte[] tag, byte[] aad, bool encrypt)
        {
            if (key == null || (key.Length != 16 && key.Length != 24 && key.Length != 32))
            {
                throw new ArgumentException("Key must be 16, 24, or 32 bytes.");
            }
            if (nonce == null || nonce.Length != NonceSize)
            {
                throw new ArgumentException("Nonce must be 12 bytes.");
            }
            if (tag == null || tag.Length != TagSize)
            {
                throw new ArgumentException("Tag must be 16 bytes.");
            }
            if (input == null)
            {
                throw new ArgumentNullException("input");
            }
            if (output == null || output.Length != input.Length)
            {
                throw new ArgumentException("Output must be the same length as input.");
            }
            if (aad == null)
            {
                aad = new byte[0];
            }

            IntPtr hAlg = IntPtr.Zero;
            IntPtr hKey = IntPtr.Zero;
            GCHandle nonceHandle = default(GCHandle);
            GCHandle tagHandle = default(GCHandle);
            GCHandle aadHandle = default(GCHandle);

            try
            {
                int status = BCryptOpenAlgorithmProvider(out hAlg, "AES", null, 0);
                Check(status, "BCryptOpenAlgorithmProvider");

                byte[] mode = Encoding.Unicode.GetBytes("ChainingModeGCM\0");
                status = BCryptSetProperty(hAlg, "ChainingMode", mode, mode.Length, 0);
                Check(status, "BCryptSetProperty");

                status = BCryptGenerateSymmetricKey(hAlg, out hKey, IntPtr.Zero, 0, key, key.Length, 0);
                Check(status, "BCryptGenerateSymmetricKey");

                nonceHandle = GCHandle.Alloc(nonce, GCHandleType.Pinned);
                tagHandle = GCHandle.Alloc(tag, GCHandleType.Pinned);
                aadHandle = GCHandle.Alloc(aad, GCHandleType.Pinned);

                BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info = new BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO();
                info.cbSize = Marshal.SizeOf(typeof(BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO));
                info.dwInfoVersion = 1;
                info.pbNonce = nonceHandle.AddrOfPinnedObject();
                info.cbNonce = nonce.Length;
                info.pbTag = tagHandle.AddrOfPinnedObject();
                info.cbTag = tag.Length;
                info.pbAuthData = aadHandle.AddrOfPinnedObject();
                info.cbAuthData = aad.Length;

                int result = 0;
                if (encrypt)
                {
                    status = BCryptEncrypt(hKey, input, input.Length, ref info, null, 0, output, output.Length, out result, 0);
                    Check(status, "BCryptEncrypt");
                }
                else
                {
                    status = BCryptDecrypt(hKey, input, input.Length, ref info, null, 0, output, output.Length, out result, 0);
                    Check(status, "BCryptDecrypt");
                }
            }
            finally
            {
                if (nonceHandle.IsAllocated) { nonceHandle.Free(); }
                if (tagHandle.IsAllocated) { tagHandle.Free(); }
                if (aadHandle.IsAllocated) { aadHandle.Free(); }
                if (hKey != IntPtr.Zero) { BCryptDestroyKey(hKey); }
                if (hAlg != IntPtr.Zero) { BCryptCloseAlgorithmProvider(hAlg, 0); }
            }
        }

        private static void Check(int status, string api)
        {
            if (status != 0)
            {
                throw new InvalidOperationException(api + " failed: 0x" + status.ToString("X8"));
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO
        {
            public int cbSize;
            public int dwInfoVersion;
            public IntPtr pbNonce;
            public int cbNonce;
            public IntPtr pbAuthData;
            public int cbAuthData;
            public IntPtr pbTag;
            public int cbTag;
            public IntPtr pbMacContext;
            public int cbMacContext;
            public int cbAAD;
            public long cbData;
            public uint dwFlags;
        }

        [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
        private static extern int BCryptOpenAlgorithmProvider(out IntPtr phAlgorithm, string pszAlgId, string pszImplementation, uint dwFlags);

        [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
        private static extern int BCryptSetProperty(IntPtr hObject, string pszProperty, byte[] pbInput, int cbInput, uint dwFlags);

        [DllImport("bcrypt.dll")]
        private static extern int BCryptGenerateSymmetricKey(IntPtr hAlgorithm, out IntPtr phKey, IntPtr pbKeyObject, int cbKeyObject, byte[] pbSecret, int cbSecret, uint dwFlags);

        [DllImport("bcrypt.dll")]
        private static extern int BCryptEncrypt(IntPtr hKey, byte[] pbInput, int cbInput, ref BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO pPaddingInfo, byte[] pbIV, int cbIV, byte[] pbOutput, int cbOutput, out int pcbResult, uint dwFlags);

        [DllImport("bcrypt.dll")]
        private static extern int BCryptDecrypt(IntPtr hKey, byte[] pbInput, int cbInput, ref BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO pPaddingInfo, byte[] pbIV, int cbIV, byte[] pbOutput, int cbOutput, out int pcbResult, uint dwFlags);

        [DllImport("bcrypt.dll")]
        private static extern int BCryptDestroyKey(IntPtr hKey);

        [DllImport("bcrypt.dll")]
        private static extern int BCryptCloseAlgorithmProvider(IntPtr hAlgorithm, uint dwFlags);
    }
}
'@
}

function ConvertFrom-SecureStringBytes {
    param(
        [Parameter(Mandatory = $true)]
        [SecureString]$SecureString
    )

    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString)
    try {
        $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
        if ([string]::IsNullOrEmpty($plain)) {
            throw 'Password cannot be empty.'
        }
        return , [Text.Encoding]::UTF8.GetBytes($plain)
    }
    finally {
        if ($bstr -ne [IntPtr]::Zero) {
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
        }
    }
}

function Test-SecureStringEqual {
    param(
        [Parameter(Mandatory = $true)]
        [SecureString]$Left,
        [Parameter(Mandatory = $true)]
        [SecureString]$Right
    )

    if ($Left.Length -ne $Right.Length) {
        return $false
    }

    $leftPtr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Left)
    $rightPtr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Right)
    try {
        $leftText = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($leftPtr)
        $rightText = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($rightPtr)
        return $leftText -ceq $rightText
    }
    finally {
        if ($leftPtr -ne [IntPtr]::Zero) {
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($leftPtr)
        }
        if ($rightPtr -ne [IntPtr]::Zero) {
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($rightPtr)
        }
    }
}

function Read-EncryptionPassword {
    param(
        [switch]$Confirm
    )

    $first = Read-Host 'Encryption password' -AsSecureString
    if ($first.Length -eq 0) {
        throw 'Password cannot be empty.'
    }

    if ($Confirm) {
        $second = Read-Host 'Confirm password' -AsSecureString
        if (-not (Test-SecureStringEqual -Left $first -Right $second)) {
            throw 'Passwords do not match.'
        }
        if ($first.Length -lt 8) {
            Write-Warning 'Password is shorter than 8 characters. A longer password is strongly recommended.'
        }
    }

    return $first
}

function Get-RandomBytes {
    param(
        [Parameter(Mandatory = $true)]
        [int]$Count
    )

    $bytes = New-Object byte[] $Count
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $rng.GetBytes($bytes)
        return , $bytes
    }
    finally {
        $rng.Dispose()
    }
}

function Get-Pbkdf2Key {
    param(
        [Parameter(Mandatory = $true)]
        [byte[]]$PasswordBytes,
        [Parameter(Mandatory = $true)]
        [byte[]]$Salt,
        [Parameter(Mandatory = $true)]
        [int]$Iterations
    )

    $kdf = New-Object System.Security.Cryptography.Rfc2898DeriveBytes(
        $PasswordBytes,
        $Salt,
        $Iterations,
        [Security.Cryptography.HashAlgorithmName]::SHA256
    )
    try {
        return , $kdf.GetBytes(32)
    }
    finally {
        $kdf.Dispose()
    }
}

function ConvertTo-LittleEndianBytes {
    param([uint32]$Value)

    $bytes = [BitConverter]::GetBytes($Value)
    if (-not [BitConverter]::IsLittleEndian) {
        [Array]::Reverse($bytes)
    }
    return , $bytes
}

function ConvertFrom-LittleEndianUInt32 {
    param([byte[]]$Bytes, [int]$Offset)

    $slice = New-Object byte[] 4
    [Buffer]::BlockCopy($Bytes, $Offset, $slice, 0, 4)
    if (-not [BitConverter]::IsLittleEndian) {
        [Array]::Reverse($slice)
    }
    return [BitConverter]::ToUInt32($slice, 0)
}

function Get-HeaderAad {
    param([byte[]]$FileBytes)

    $aad = New-Object byte[] 38
    [Buffer]::BlockCopy($FileBytes, 0, $aad, 0, 38)
    return , $aad
}

function ConvertTo-FcryptedBytes {
    param(
        [Parameter(Mandatory = $true)]
        [SecureString]$Password,
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [byte[]]$Plaintext,
        [Parameter(Mandatory = $true)]
        [int]$Iterations
    )

    Initialize-FileCryptoratorCrypto

    $passwordBytes = $null
    $key = $null
    try {
        $passwordBytes = [byte[]](ConvertFrom-SecureStringBytes -SecureString $Password)
        $salt = [byte[]](Get-RandomBytes -Count $script:FcSaltSize)
        $nonce = [byte[]](Get-RandomBytes -Count $script:FcNonceSize)
        $key = [byte[]](Get-Pbkdf2Key -PasswordBytes $passwordBytes -Salt $salt -Iterations $Iterations)

        $ciphertext = New-Object byte[] $Plaintext.Length
        $tag = New-Object byte[] $script:FcTagSize

        $header = New-Object byte[] $script:FcHeaderSize
        $magic = [Text.Encoding]::ASCII.GetBytes($script:FcMagicText)
        [Buffer]::BlockCopy($magic, 0, $header, 0, 4)
        $header[4] = $script:FcVersion
        $header[5] = $script:FcKdfPbkdf2Sha256
        $iterBytes = [byte[]](ConvertTo-LittleEndianBytes -Value ([uint32]$Iterations))
        [Buffer]::BlockCopy($iterBytes, 0, $header, 6, 4)
        [Buffer]::BlockCopy($salt, 0, $header, 10, $script:FcSaltSize)
        [Buffer]::BlockCopy($nonce, 0, $header, 26, $script:FcNonceSize)

        $aad = [byte[]](Get-HeaderAad -FileBytes $header)
        [FileCryptorator.AesGcmCrypto]::Encrypt($key, $nonce, $Plaintext, $ciphertext, $tag, $aad)
        [Buffer]::BlockCopy($tag, 0, $header, 38, $script:FcTagSize)

        $blob = New-Object byte[] ($script:FcHeaderSize + $ciphertext.Length)
        [Buffer]::BlockCopy($header, 0, $blob, 0, $script:FcHeaderSize)
        if ($ciphertext.Length -gt 0) {
            [Buffer]::BlockCopy($ciphertext, 0, $blob, $script:FcHeaderSize, $ciphertext.Length)
        }
        return , $blob
    }
    finally {
        if ($passwordBytes) { [Array]::Clear($passwordBytes, 0, $passwordBytes.Length) }
        if ($key) { [Array]::Clear($key, 0, $key.Length) }
    }
}

function ConvertFrom-FcryptedBytes {
    param(
        [Parameter(Mandatory = $true)]
        [SecureString]$Password,
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [byte[]]$FileBytes,
        [Parameter(Mandatory = $true)]
        [string]$SourceFile
    )

    Initialize-FileCryptoratorCrypto

    if ($FileBytes.Length -lt $script:FcHeaderSize) {
        throw "File '$SourceFile' is too short to be a FileCryptorator file."
    }

    $magic = [Text.Encoding]::ASCII.GetString($FileBytes, 0, 4)
    if ($magic -ne $script:FcMagicText) {
        throw "File '$SourceFile' is not a FileCryptorator v1 file (expected $script:FcMagicText header). Older AES-CBC files are not compatible."
    }

    $version = $FileBytes[4]
    if ($version -ne $script:FcVersion) {
        throw "File '$SourceFile' has unsupported version $version."
    }

    $kdf = $FileBytes[5]
    if ($kdf -ne $script:FcKdfPbkdf2Sha256) {
        throw "File '$SourceFile' uses unsupported key derivation $kdf."
    }

    $storedIterations = [int](ConvertFrom-LittleEndianUInt32 -Bytes $FileBytes -Offset 6)
    if ($storedIterations -lt $script:FcMinIterations -or $storedIterations -gt $script:FcMaxIterations) {
        throw "File '$SourceFile' requests $storedIterations PBKDF2 iterations, which is outside the accepted range."
    }

    $salt = New-Object byte[] $script:FcSaltSize
    $nonce = New-Object byte[] $script:FcNonceSize
    $tag = New-Object byte[] $script:FcTagSize
    [Buffer]::BlockCopy($FileBytes, 10, $salt, 0, $script:FcSaltSize)
    [Buffer]::BlockCopy($FileBytes, 26, $nonce, 0, $script:FcNonceSize)
    [Buffer]::BlockCopy($FileBytes, 38, $tag, 0, $script:FcTagSize)

    $cipherLength = $FileBytes.Length - $script:FcHeaderSize
    $ciphertext = New-Object byte[] $cipherLength
    if ($cipherLength -gt 0) {
        [Buffer]::BlockCopy($FileBytes, $script:FcHeaderSize, $ciphertext, 0, $cipherLength)
    }

    $passwordBytes = $null
    $key = $null
    try {
        $passwordBytes = [byte[]](ConvertFrom-SecureStringBytes -SecureString $Password)
        $key = [byte[]](Get-Pbkdf2Key -PasswordBytes $passwordBytes -Salt $salt -Iterations $storedIterations)
        $aad = [byte[]](Get-HeaderAad -FileBytes $FileBytes)
        $plaintext = New-Object byte[] $cipherLength
        try {
            [FileCryptorator.AesGcmCrypto]::Decrypt($key, $nonce, $ciphertext, $tag, $plaintext, $aad)
        }
        catch {
            throw "Decryption failed for '$SourceFile'. Wrong password, or the file was modified."
        }
        return , $plaintext
    }
    finally {
        if ($passwordBytes) { [Array]::Clear($passwordBytes, 0, $passwordBytes.Length) }
        if ($key) { [Array]::Clear($key, 0, $key.Length) }
    }
}

function Resolve-ProviderPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$InputPath
    )

    if ($InputPath -like 'Microsoft.PowerShell.Core\FileSystem::*') {
        return $InputPath.Substring('Microsoft.PowerShell.Core\FileSystem::'.Length)
    }
    return $InputPath
}

function ConvertTo-FullFilesystemPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$InputPath
    )

    $raw = Resolve-ProviderPath -InputPath $InputPath
    if ([IO.Path]::IsPathRooted($raw)) {
        return [IO.Path]::GetFullPath($raw)
    }

    $base = (Get-Location -PSProvider FileSystem).ProviderPath
    return [IO.Path]::GetFullPath((Join-Path $base $raw))
}

function Resolve-OutputPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$SourcePath,
        [string]$Destination,
        [Parameter(Mandatory = $true)]
        [ValidateSet('Encrypt', 'Decrypt')]
        [string]$Mode,
        [switch]$Force
    )

    $sourceFull = ConvertTo-FullFilesystemPath -InputPath $SourcePath
    $sourceName = [IO.Path]::GetFileName($sourceFull)
    $sourceDir = [IO.Path]::GetDirectoryName($sourceFull)

    if ([string]::IsNullOrWhiteSpace($Destination)) {
        if ($Mode -eq 'Encrypt') {
            $out = $sourceFull + $script:FcExtension
        }
        elseif ($sourceName.EndsWith($script:FcExtension, [StringComparison]::OrdinalIgnoreCase)) {
            $out = Join-Path $sourceDir $sourceName.Substring(0, $sourceName.Length - $script:FcExtension.Length)
        }
        else {
            $out = $sourceFull + '.decrypted'
        }
    }
    elseif ((Test-Path -LiteralPath $Destination -PathType Container)) {
        if ($Mode -eq 'Encrypt') {
            $out = Join-Path $Destination ($sourceName + $script:FcExtension)
        }
        elseif ($sourceName.EndsWith($script:FcExtension, [StringComparison]::OrdinalIgnoreCase)) {
            $out = Join-Path $Destination $sourceName.Substring(0, $sourceName.Length - $script:FcExtension.Length)
        }
        else {
            $out = Join-Path $Destination $sourceName
        }
    }
    else {
        $out = ConvertTo-FullFilesystemPath -InputPath $Destination
        $parent = [IO.Path]::GetDirectoryName($out)
        if ($parent -and -not (Test-Path -LiteralPath $parent -PathType Container)) {
            throw "Destination folder '$parent' does not exist."
        }
    }

    $outFull = ConvertTo-FullFilesystemPath -InputPath $out
    if ($outFull.Equals($sourceFull, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Output path would overwrite the source file: $outFull"
    }

    if ((Test-Path -LiteralPath $outFull) -and -not $Force) {
        throw "Output already exists: $outFull (use -Force to overwrite)"
    }

    return $outFull
}

function Write-AtomicFile {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [byte[]]$Bytes
    )

    $directory = [IO.Path]::GetDirectoryName($Path)
    $tempPath = Join-Path $directory ([IO.Path]::GetFileName($Path) + '.partial')
    try {
        [IO.File]::WriteAllBytes($tempPath, $Bytes)
        if (Test-Path -LiteralPath $Path) {
            Remove-Item -LiteralPath $Path -Force
        }
        Move-Item -LiteralPath $tempPath -Destination $Path
    }
    catch {
        if (Test-Path -LiteralPath $tempPath) {
            Remove-Item -LiteralPath $tempPath -Force -ErrorAction SilentlyContinue
        }
        throw
    }
}

function Protect-UserFile {
    param(
        [Parameter(Mandatory = $true)]
        [string]$SourcePath,
        [string]$Destination,
        [Parameter(Mandatory = $true)]
        [SecureString]$Password,
        [Parameter(Mandatory = $true)]
        [int]$Iterations,
        [switch]$Force
    )

    $sourceFull = ConvertTo-FullFilesystemPath -InputPath $SourcePath
    if (-not (Test-Path -LiteralPath $sourceFull -PathType Leaf)) {
        throw "File not found: $sourceFull"
    }

    $info = Get-Item -LiteralPath $sourceFull
    if ($info.Length -gt [int]::MaxValue) {
        throw "File '$sourceFull' is larger than 2 GB. This script loads the file into memory."
    }
    if ($info.Length -ge $script:FcMemoryWarnBytes) {
        Write-Warning ("Loading a {0:N1} MB file into memory." -f ($info.Length / 1MB))
    }

    $output = Resolve-OutputPath -SourcePath $sourceFull -Destination $Destination -Mode Encrypt -Force:$Force
    $plaintext = [IO.File]::ReadAllBytes($sourceFull)
    try {
        $blob = ConvertTo-FcryptedBytes -Password $Password -Plaintext $plaintext -Iterations $Iterations
        Write-AtomicFile -Path $output -Bytes $blob
        return $output
    }
    finally {
        [Array]::Clear($plaintext, 0, $plaintext.Length)
    }
}

function Unprotect-UserFile {
    param(
        [Parameter(Mandatory = $true)]
        [string]$SourcePath,
        [string]$Destination,
        [Parameter(Mandatory = $true)]
        [SecureString]$Password,
        [switch]$Force
    )

    $sourceFull = ConvertTo-FullFilesystemPath -InputPath $SourcePath
    if (-not (Test-Path -LiteralPath $sourceFull -PathType Leaf)) {
        throw "File not found: $sourceFull"
    }

    $output = Resolve-OutputPath -SourcePath $sourceFull -Destination $Destination -Mode Decrypt -Force:$Force
    $fileBytes = [IO.File]::ReadAllBytes($sourceFull)
    try {
        $plaintext = ConvertFrom-FcryptedBytes -Password $Password -FileBytes $fileBytes -SourceFile $sourceFull
        try {
            Write-AtomicFile -Path $output -Bytes $plaintext
            return $output
        }
        finally {
            [Array]::Clear($plaintext, 0, $plaintext.Length)
        }
    }
    finally {
        [Array]::Clear($fileBytes, 0, $fileBytes.Length)
    }
}

function Get-FileFromDialog {
    param(
        [string]$Title = 'Select a file',
        [string]$Filter = 'All files (*.*)|*.*'
    )

    try {
        Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
        $dialog = New-Object System.Windows.Forms.OpenFileDialog
        $dialog.Title = $Title
        $dialog.Filter = $Filter
        $dialog.Multiselect = $false
        $dialog.CheckFileExists = $true
        $result = $dialog.ShowDialog()
        if ($result -ne [Windows.Forms.DialogResult]::OK) {
            return $null
        }
        return $dialog.FileName
    }
    catch {
        Write-Warning 'File dialog is unavailable. Enter a path instead.'
        $typed = Read-Host 'File path'
        if ([string]::IsNullOrWhiteSpace($typed)) {
            return $null
        }
        return $typed.Trim('"')
    }
}

function Invoke-FileCryptoratorSelfTest {
    $workRoot = Join-Path ([IO.Path]::GetTempPath()) ('FileCryptorator-test-' + [guid]::NewGuid().ToString('N'))
    $passed = 0
    $failed = 0

    function Write-TestResult {
        param([bool]$Ok, [string]$Name)
        if ($Ok) {
            Write-Host "  PASS  $Name"
            $script:selfTestPassed++
        }
        else {
            Write-Host "  FAIL  $Name" -ForegroundColor Red
            $script:selfTestFailed++
        }
    }

    $script:selfTestPassed = 0
    $script:selfTestFailed = 0

    New-Item -ItemType Directory -Path $workRoot -Force | Out-Null
    try {
        $password = ConvertTo-SecureString 'FileCryptorator-self-test-password' -AsPlainText -Force
        $wrong = ConvertTo-SecureString 'wrong-password-value' -AsPlainText -Force
        $plainPath = Join-Path $workRoot 'sample.txt'
        $payload = [Text.Encoding]::UTF8.GetBytes("FileCryptorator self-test`r`n" + ('0123456789' * 200))
        [IO.File]::WriteAllBytes($plainPath, $payload)

        $emptyPath = Join-Path $workRoot 'empty.bin'
        [IO.File]::WriteAllBytes($emptyPath, [byte[]]@())

        $enc1 = Protect-UserFile -SourcePath $plainPath -Password $password -Iterations 100000 -Force
        $enc2 = Protect-UserFile -SourcePath $plainPath -Destination (Join-Path $workRoot 'sample2.txt.fcrypt') -Password $password -Iterations 100000 -Force
        $decPath = Join-Path $workRoot 'restored.txt'
        $restored = Unprotect-UserFile -SourcePath $enc1 -Destination $decPath -Password $password -Force

        $originalHash = (Get-FileHash -LiteralPath $plainPath -Algorithm SHA256).Hash
        $restoredHash = (Get-FileHash -LiteralPath $restored -Algorithm SHA256).Hash
        Write-TestResult -Ok ($originalHash -eq $restoredHash) -Name 'round-trip hash'

        $blob1 = [IO.File]::ReadAllBytes($enc1)
        $blob2 = [IO.File]::ReadAllBytes($enc2)
        $sameCipher = ($blob1.Length -eq $blob2.Length)
        if ($sameCipher) {
            $differs = $false
            for ($i = 0; $i -lt $blob1.Length; $i++) {
                if ($blob1[$i] -ne $blob2[$i]) { $differs = $true; break }
            }
            $sameCipher = -not $differs
        }
        Write-TestResult -Ok (-not $sameCipher) -Name 'unique salt/nonce per encrypt'

        $emptyEnc = Protect-UserFile -SourcePath $emptyPath -Password $password -Iterations 100000 -Force
        $emptyOut = Join-Path $workRoot 'empty.out'
        $emptyRestored = Unprotect-UserFile -SourcePath $emptyEnc -Destination $emptyOut -Password $password -Force
        Write-TestResult -Ok ((Get-Item -LiteralPath $emptyRestored).Length -eq 0) -Name 'empty file round-trip'

        $wrongFailed = $false
        try {
            Unprotect-UserFile -SourcePath $enc1 -Destination (Join-Path $workRoot 'wrong.txt') -Password $wrong -Force | Out-Null
        }
        catch {
            $wrongFailed = $true
        }
        Write-TestResult -Ok $wrongFailed -Name 'wrong password rejected'

        $tampered = [byte[]]$blob1.Clone()
        $tampered[$tampered.Length - 1] = $tampered[$tampered.Length - 1] -bxor 0xFF
        $tamperPath = Join-Path $workRoot 'tampered.fcrypt'
        [IO.File]::WriteAllBytes($tamperPath, $tampered)
        $tamperFailed = $false
        $tamperOut = Join-Path $workRoot 'tamper-out.txt'
        try {
            Unprotect-UserFile -SourcePath $tamperPath -Destination $tamperOut -Password $password -Force | Out-Null
        }
        catch {
            $tamperFailed = $true
        }
        $noLeak = -not (Test-Path -LiteralPath $tamperOut)
        Write-TestResult -Ok ($tamperFailed -and $noLeak) -Name 'tamper detection (GCM tag)'

        $overwriteFailed = $false
        try {
            Protect-UserFile -SourcePath $plainPath -Destination $enc1 -Password $password -Iterations 100000 | Out-Null
        }
        catch {
            $overwriteFailed = $_.Exception.Message -like '*already exists*'
        }
        Write-TestResult -Ok $overwriteFailed -Name 'refuse overwrite without -Force'

        $passed = $script:selfTestPassed
        $failed = $script:selfTestFailed
        Write-Host "Result: $passed passed, $failed failed"
        return [PSCustomObject]@{
            Passed = $passed
            Failed = $failed
        }
    }
    finally {
        if (Test-Path -LiteralPath $workRoot) {
            Remove-Item -LiteralPath $workRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Show-InteractiveMenu {
    Write-Host $script:FcLogo -ForegroundColor Magenta
    Write-Host
    Write-Host '  Password-based AES-256-GCM file encryption' -ForegroundColor Green
    Write-Host '  Originals are left in place. Responsible use only.' -ForegroundColor Green
    Write-Host
    Write-Host '  1: Encrypt a file'
    Write-Host '  2: Decrypt a file'
    Write-Host '  Q: Quit'
    Write-Host
}

function Invoke-InteractiveSession {
    while ($true) {
        Show-InteractiveMenu
        $selection = Read-Host 'Select 1, 2, or Q'
        switch -Regex ($selection) {
            '^1$' {
                $file = Get-FileFromDialog -Title 'Select a file to encrypt'
                if (-not $file) {
                    Write-Host 'Cancelled.' -ForegroundColor Yellow
                    return
                }
                $pw = if ($Password) { $Password } else { Read-EncryptionPassword -Confirm }
                $out = Protect-UserFile -SourcePath $file -Destination $Destination -Password $pw -Iterations $Iterations -Force:$Force
                Write-Host "Encrypted file: $out" -ForegroundColor Green
                return
            }
            '^2$' {
                $file = Get-FileFromDialog -Title 'Select a file to decrypt' -Filter "FileCryptorator (*.fcrypt)|*.fcrypt|All files (*.*)|*.*"
                if (-not $file) {
                    Write-Host 'Cancelled.' -ForegroundColor Yellow
                    return
                }
                $pw = if ($Password) { $Password } else { Read-EncryptionPassword }
                $out = Unprotect-UserFile -SourcePath $file -Destination $Destination -Password $pw -Force:$Force
                Write-Host "Decrypted file: $out" -ForegroundColor Green
                return
            }
            '^[Qq]$' { return }
            default {
                Write-Host 'Enter 1, 2, or Q.' -ForegroundColor Red
            }
        }
    }
}

function Get-InferredMode {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,
        [switch]$Encrypt,
        [switch]$Decrypt
    )

    if ($Encrypt) { return 'Encrypt' }
    if ($Decrypt) { return 'Decrypt' }

    $name = [IO.Path]::GetFileName((Resolve-ProviderPath -InputPath $FilePath))
    if ($name.EndsWith($script:FcExtension, [StringComparison]::OrdinalIgnoreCase)) {
        return 'Decrypt'
    }
    return 'Encrypt'
}

    Initialize-FileCryptoratorDefaults
    $script:pendingPaths = New-Object System.Collections.Generic.List[string]
}

process {
    foreach ($item in @($Path)) {
        if (-not [string]::IsNullOrWhiteSpace($item)) {
            $script:pendingPaths.Add((Resolve-ProviderPath -InputPath $item))
        }
    }
}

end {
    if ($MyInvocation.InvocationName -eq '.') {
        return
    }

    $failed = 0
    try {
        if ($SelfTest -or $PSCmdlet.ParameterSetName -eq 'SelfTest') {
            $result = Invoke-FileCryptoratorSelfTest
            if ($result.Failed -gt 0) {
                throw 'Self-test failed.'
            }
            return
        }

        if ($script:pendingPaths.Count -eq 0) {
            Invoke-InteractiveSession
            return
        }

        $firstMode = Get-InferredMode -FilePath $script:pendingPaths[0] -Encrypt:$Encrypt -Decrypt:$Decrypt
        $needConfirm = ($firstMode -eq 'Encrypt')
        $resolvedPassword = $Password
        if (-not $resolvedPassword) {
            $resolvedPassword = Read-EncryptionPassword -Confirm:$needConfirm
        }
        elseif ($resolvedPassword.Length -eq 0) {
            throw 'Password cannot be empty.'
        }

        $index = 0
        $total = $script:pendingPaths.Count
        foreach ($item in $script:pendingPaths) {
            $index++
            $mode = Get-InferredMode -FilePath $item -Encrypt:$Encrypt -Decrypt:$Decrypt
            Write-Progress -Activity 'FileCryptorator' -Status "$mode $item" -PercentComplete (($index / $total) * 100)
            try {
                if ($mode -eq 'Encrypt') {
                    $out = Protect-UserFile -SourcePath $item -Destination $Destination -Password $resolvedPassword -Iterations $Iterations -Force:$Force
                    Write-Host "Encrypted: $out"
                }
                else {
                    $out = Unprotect-UserFile -SourcePath $item -Destination $Destination -Password $resolvedPassword -Force:$Force
                    Write-Host "Decrypted: $out"
                }
            }
            catch {
                Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
                $failed++
            }
        }
        Write-Progress -Activity 'FileCryptorator' -Completed
    }
    catch {
        Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
        throw
    }

    if ($failed -gt 0) {
        throw "$failed file(s) failed."
    }
}
