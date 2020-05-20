<#
.SYNOPSIS 
This scriptis for testing purposes only. Malicious use of this script is prohibitted. 
Encrypt or Decrypt a single file.

.DESCRIPTION
Encrypts or Decrypts files using AES.

.NOTES
Author of FileCryptorator script @cyb3rw01f
#>

$logo = @"
	=================================================================
				   _                         ___  _  __ 
			 ___ _   _| |__   ___ _ ____      __/ _ \/ |/ _|
			/ __| | | | '_ \ / _ \ '__\ \ /\ / / | | | | |_ 
		       | (__| |_| | |_) |  __/ |   \ V  V /| |_| | |  _|
			\___|\__, |_.__/ \___|_|    \_/\_/  \___/|_|_|  
			     |___/                                      
		
	==================================================================
		 *     *    *     /\__/\  *    ---    *
                   *            /      \    /     \    
                        *   *  |  -  -  |  |       |*   
                 *   __________| \     /|  |       |    
                   /              \ T / |   \     /    
                 /                      |  *  ---
                |  ||     |    |       /             *
                |  ||    /______\     / |*     *
                |  | \  |  /     \   /  |
                 \/   | |\ \      | | \ \
                      | | \ \     | |  \ \
                      | |  \ \    | |   \ \
                      '''   '''   '''    ''
		             @cyberw01f								  
"@

$label = @"  
                
                       Responsible use only permited
"@

Function Export-EncryptedFile
{
    param(
        [string]$InFilePath,
        [string]$OutFilePath,
        [string]$Password
    )
    begin
    {
        Function Get-SHA256Hash
        {
            param(
                [string]$inputString
            )
            process
            {
                [System.Security.Cryptography.SHA256]$SHA256 = [System.Security.Cryptography.SHA256]::Create()
                return $SHA256.ComputeHash([System.Text.ASCIIEncoding]::UTF8.GetBytes($inputString))
            }
        }
    }
    process
    {
        [System.Security.Cryptography.AesCryptoServiceProvider]$Aes =  [System.Security.Cryptography.AesCryptoServiceProvider]::new()
        $Aes.BlockSize = 128
        $Aes.KeySize = 256
        $Aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $Aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        $Aes.GenerateIV()
        [byte[]]$IV = $Aes.IV
        [byte[]]$Key = Get-SHA256Hash -inputString $Password
        [System.IO.FileStream]$FileStreamOut = [System.IO.FileStream]::new($OutFilePath,[System.IO.FileMode]::Create)
        [System.Security.Cryptography.ICryptoTransform]$ICryptoTransform = $Aes.CreateEncryptor($Key,$IV)
        [System.Security.Cryptography.CryptoStream]$CryptoStream = [System.Security.Cryptography.CryptoStream]::new($FileStreamOut, $ICryptoTransform, [System.Security.Cryptography.CryptoStreamMode]::Write)
        [System.IO.FileStream]$FileStreamIn = [System.IO.FileStream]::new($InFilePath,[System.IO.FileMode]::Open)
 
        $FileStreamOut.Write($IV,0,$IV.Count)
        $DataAvailable = $true
        [int]$Data
 
        While ($DataAvailable)
        {
            $Data = $FileStreamIn.ReadByte()
            if($Data -ne -1)
            {
                $CryptoStream.WriteByte([byte]$Data)
            }
            else
            {
                $DataAvailable = $false
            }
        }
 
        $FileStreamIn.Dispose()
        $CryptoStream.Dispose()
        $FileStreamOut.Dispose()
 
    }
}
 
Function Import-EncryptedFile
{
    param(
        [string]$InFilePath,
        [string]$OutFilePath,
        [string]$Password
    )
    begin
    {
        Function Get-SHA256Hash
        {
            param(
                [string]$inputString
            )
            process
            {
                [System.Security.Cryptography.SHA256]$SHA256 = [System.Security.Cryptography.SHA256]::Create()
                return $SHA256.ComputeHash([System.Text.ASCIIEncoding]::UTF8.GetBytes($inputString))
            }
        }
    }
    process
    {
 
        [System.IO.FileStream]$FileStreamIn = [System.IO.FileStream]::new($InFilePath,[System.IO.FileMode]::Open)
        [byte[]]$IV = New-Object byte[] 16
        $FileStreamIn.Read($IV, 0, $IV.Length)
 
        [System.Security.Cryptography.AesCryptoServiceProvider]$Aes =  [System.Security.Cryptography.AesCryptoServiceProvider]::new()
        $Aes.BlockSize = 128
        $Aes.KeySize = 256
        $Aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $Aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        [byte[]]$Key = Get-SHA256Hash -inputString $Password
 
 
        [System.IO.FileStream]$FileStreamOut = [System.IO.FileStream]::new($OutFilePath,[System.IO.FileMode]::Create)
        [System.Security.Cryptography.ICryptoTransform]$ICryptoTransform = $Aes.CreateDecryptor($Key,$IV)
        [System.Security.Cryptography.CryptoStream]$CryptoStream = [System.Security.Cryptography.CryptoStream]::new($FileStreamIn, $ICryptoTransform, [System.Security.Cryptography.CryptoStreamMode]::Read)
 
        $DataAvailable = $true
        [int]$Data
 
        While ($DataAvailable)
        {
 
            $Data = $CryptoStream.ReadByte()
            if($Data -ne -1)
            {
                $FileStreamOut.WriteByte([byte]$Data)
            }
            else
            {
                $DataAvailable = $false
            }
        }
 
        $FileStreamIn.Dispose()
        $CryptoStream.Dispose()
        $FileStreamOut.Dispose()
 
    }
}
 
Function Get-File
{
Add-Type -AssemblyName System.Windows.Forms
$FileBrowser = New-Object System.Windows.Forms.OpenFileDialog -Property @{
    Multiselect = $false # When set to $true multiple files can be chosen
}
 
[void]$FileBrowser.ShowDialog()
 
$script:inFileName = $FileBrowser.FileName;
$script:file = $FileBrowser.SafeFileName;
 
If($FileBrowser.FileNames -like "*\*") {
 
        # Do something 
        $FileBrowser.FileName #Lists selected files (optional)
        
 
}
 
else {
    Write-Host -f Green  "File select cancelled by user"
    Exit
}
 
}
 
function Show-Menu
{
     param (
           [string]$Title = 'Are you encrypting or decrypting a file?'
     )
     #cls
     Write-Host "================ $Title ================"
 
     Write-Host "1: Encrypt File"
     Write-Host "2: Decrypt File"
     
}
 
function Validate-Input
{
Show-Menu –Title 'Select Encrypt or Decrypt'
$selection = Read-Host "Please select 1 or 2"
if ($selection -eq "1") 
    {
        $paswd = Read-Host "Please enter a password for hashing"
        Get-File
        $outFileName = "$($ENV:UserProfile)\Desktop\$file.encrypted"
        Export-EncryptedFile -InFilePath $script:inFileName -OutFilePath $outFileName -Password $paswd
        Write-Host -f Green "Your encrypted file is located at"
        Write-Host -f Yellow "$($ENV:UserProfile)\Desktop\$file.encrypted"
        exit
    }
 
        elseif ($selection -eq "2") 
        {
            $paswd = Read-Host "Please enter password used during file excryption "
            Get-File
            $outFileName = "$($ENV:UserProfile)\Desktop\$file.decrypted"
            Import-EncryptedFile -InFilePath $script:inFileName -OutFilePath $outFileName -Password $paswd
            Write-Host -f Green "Your decrypted file is located at $($ENV:UserProfile)\Desktop\$file.decrypt"
            Write-Host -f Yellow "$($ENV:UserProfile)\Desktop\$file.decrypted"
            exit
        }
 
         else 
         {
            Write-Host -f red "Error - A character other than a 1 or 2 was typed, please try again"; Validate-Input
         }
}
Write-Host -f Magenta $logo
Write-Host
Write-Host -f Green $label 
Validate-Input
