<#
.SYNOPSIS
    A password manager that stores encrypted passwords in a file.
.DESCRIPTION
    This script implements a password manager that allows the user to store and retrieve passwords for various services. The passwords are encrypted using a master password that is securely stored in an encrypted file.
.PARAMETER PasswordFile
    The path to the password file. If the file does not exist, it will be created.
.PARAMETER MasterPasswordFile
    The path to the file containing the encrypted master password. If the file does not exist, it will be created.
.EXAMPLE
    .\PasswordManager.ps1 -PasswordFile "C:\Passwords.json" -MasterPasswordFile "C:\MasterPassword.txt"
#>

param (
    [Parameter(Mandatory = $true)]
    [SecureString]$PasswordFile,

    [Parameter(Mandatory = $true)]
    [SecureString]$MasterPasswordFile
)

# Function to encrypt a string using a password
function Encrypt-String {
    param (
        [Parameter(Mandatory = $true)]
        [string]$PlainText,

        [Parameter(Mandatory = $true)]
        [SecureString]$Password
    )

    $SecurePassword = ConvertTo-SecureString $Password -AsPlainText -Force
    $Key = (New-Object System.Security.Cryptography.Rfc2898DeriveBytes $SecurePassword.GetBytes(32), $SecurePassword.GetBytes(16), 1000).GetBytes(32)
    $IV = (New-Object System.Security.Cryptography.Rfc2898DeriveBytes $SecurePassword.GetBytes(32), $SecurePassword.GetBytes(16), 1000).GetBytes(16)

    $AES = New-Object System.Security.Cryptography.AesCryptoServiceProvider
    $AES.Key = $Key
    $AES.IV = $IV
    $AES.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $AES.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7

    $MemoryStream = New-Object System.IO.MemoryStream
    $CryptoStream = New-Object System.Security.Cryptography.CryptoStream $MemoryStream, $AES.CreateEncryptor(), [System.Security.Cryptography.CryptoStreamMode]::Write

    $Bytes = [System.Text.Encoding]::UTF8.GetBytes($PlainText)
    $CryptoStream.Write($Bytes, 0, $Bytes.Length)
    $CryptoStream.FlushFinalBlock()

    $EncryptedBytes = $MemoryStream.ToArray()
    $MemoryStream.Dispose()
    $CryptoStream.Dispose()

    return [Convert]::ToBase64String($EncryptedBytes)
}

# Function to decrypt a string using a password
function Decrypt-String {
    param (
        [Parameter(Mandatory = $true)]
        [string]$EncryptedText,

        [Parameter(Mandatory = $true)]
        [SecureString]$Password
    )

    $SecurePassword = ConvertTo-SecureString $Password -AsPlainText -Force
    $Key = (New-Object System.Security.Cryptography.Rfc2898DeriveBytes $SecurePassword.GetBytes(32), $SecurePassword.GetBytes(16), 1000).GetBytes(32)
    $IV = (New-Object System.Security.Cryptography.Rfc2898DeriveBytes $SecurePassword.GetBytes(32), $SecurePassword.GetBytes(16), 1000).GetBytes(16)

    $AES = New-Object System.Security.Cryptography.AesCryptoServiceProvider
    $AES.Key = $Key
    $AES.IV = $IV
    $AES.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $AES.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7

    $Encrypted
    $Bytes = [Convert]::FromBase64String($EncryptedText)
    $MemoryStream = New-Object System.IO.MemoryStream($Bytes)
    $CryptoStream = New-Object System.Security.Cryptography.CryptoStream $MemoryStream, $AES.CreateDecryptor(), [System.Security.Cryptography.CryptoStreamMode]::Read

    $StreamReader = New-Object System.IO.StreamReader $CryptoStream
    $PlainText = $StreamReader.ReadToEnd()

    $StreamReader.Dispose()
    $CryptoStream.Dispose()
    $MemoryStream.Dispose()

    return $PlainText
}

# Function to create or update the encrypted master password file

function Set-MasterPassword {
    param (
        [Parameter(Mandatory = $true)]
        [SecureString]$MasterPasswordFile
    )
    $MasterPassword = Read-Host "Enter the new master password" -AsSecureString
    $EncryptedMasterPassword = Encrypt-String -PlainText ([Convert]::ToBase64String($MasterPassword.GetBuffer())) -Password "MyPassword"

    $EncryptedMasterPassword | Out-File $MasterPasswordFile
}

# Function to get the master password from the encrypted file

function Get-MasterPassword {
    param (
        [Parameter(Mandatory = $true)]
        [SecureString]$MasterPasswordFile
    )

    if (!(Test-Path $MasterPasswordFile)) {
        Set-MasterPassword -MasterPasswordFile $MasterPasswordFile
    }

    $EncryptedMasterPassword = Get-Content $MasterPasswordFile
    $MasterPassword = Decrypt-String -EncryptedText $EncryptedMasterPassword -Password "MyPassword"

    return $MasterPassword
}

# Function to add a password to the password file

function Add-Password {
    param (
        [Parameter(Mandatory = $true)]
        [SecureString]$PasswordFile
    )

    $ServiceName = Read-Host "Enter the service name"
    $UserName = Read-Host "Enter the user name"
    $Password = Read-Host "Enter the password" -AsSecureString

    $Passwords = @{}
    if (Test-Path $PasswordFile) {
        $EncryptedPasswords = Get-Content $PasswordFile
        $Passwords = ConvertFrom-Json -InputObject (Decrypt-String -EncryptedText $EncryptedPasswords -Password (Get-MasterPassword -MasterPasswordFile $MasterPasswordFile))
    }

    $Passwords.Add($ServiceName, @{
            UserName = $UserName
            Password = [Convert]::ToBase64String($Password.GetBuffer())
        })

    $EncryptedPasswords = Encrypt-String -PlainText (ConvertTo-Json $Passwords) -Password (Get-MasterPassword -MasterPasswordFile $MasterPasswordFile)
    $EncryptedPasswords | Out-File $PasswordFile

}

# Function to get a password from the password file

function Get-Password {
    param (
        [Parameter(Mandatory = $true)]
        [SecureString]$PasswordFile
    )
}

$ServiceName = Read-Host "Enter the service name"

$Passwords = @{}
if (Test-Path $PasswordFile) {
    $EncryptedPasswords = Get-Content $PasswordFile
    $Passwords = ConvertFrom-Json -InputObject (Decrypt-String -EncryptedText $EncryptedPasswords -Password (Get-MasterPassword -MasterPasswordFile $MasterPasswordFile))
}

if ($Passwords.ContainsKey($ServiceName)) {
    $PasswordData = $Passwords[$ServiceName]
    $UserName = $PasswordData.UserName
    $Password = [System.Security.SecureString]::new()
    [Convert]::FromBase64String($PasswordData.Password) | ForEach-Object { [void]$Password.AppendChar([System.Convert]::ToChar($_)) }
}

return @{
    UserName = $UserName
    Password = $Password
}

# Function to remove a password from the password file

function Remove-Password {
    param (
        [Parameter(Mandatory = $true)]
        [SecureString]$PasswordFile
    )
}

$ServiceName = Read-Host "Enter the service name"

$Passwords = @{}
if (Test-Path $PasswordFile) {
    $EncryptedPasswords = Get-Content $PasswordFile
    $Passwords = ConvertFrom-Json -InputObject (Decrypt-String -EncryptedText $EncryptedPasswords -Password (Get-MasterPassword -MasterPasswordFile $MasterPasswordFile))
}

if ($Passwords.ContainsKey($ServiceName)) {
    $Passwords.Remove($ServiceName)

    $EncryptedPasswords = Encrypt-String -PlainText (ConvertTo-Json $Passwords) -Password (Get-MasterPassword -MasterPasswordFile $MasterPasswordFile)
    $EncryptedPasswords | Out-File $PasswordFile

    Write-Host "Password removed for service: $ServiceName"
}
else {
    Write-Host "No password found for service: $ServiceName"
}

# Function to display the main menu

function Show-MainMenu {
    param (
        [Parameter(Mandatory = $true)]
        [SecureString]$MasterPasswordFile,
        [Parameter(Mandatory = $true)]
        [SecureString]$PasswordFile
    )
}

while ($true) {
    Write-Host ""
    Write-Host "Password Manager"
    Write-Host "----------------"
    Write-Host "1. Add a password"
    Write-Host "2. Get a password"
    Write-Host "3. Remove a password"
    Write-Host "4. Exit"
    $Choice = Read-Host "Enter your choice"

    switch ($Choice) {
        "1" {
            Add-Password -PasswordFile $PasswordFile
        }
        "2" {
            $PasswordData = Get-Password -PasswordFile $PasswordFile
            if ($PasswordData) {
                Write-Host "User name: $($PasswordData.UserName)"
                Write-Host "Password: $($PasswordData.Password)"
            }
            else {
                Write-Host "No password found for service"
            }
        }
        "3" {
            Remove-Password -PasswordFile $PasswordFile
        }
        "4" {
            break
        }
        default {
            Write-Host "Invalid choice"
        }
    }
}

# Prompt the user for the master password and decrypt the password file

$MasterPassword = Read-Host "Enter the master password" -AsSecureString
$MasterPasswordFile = "C:\PasswordManager\MasterPassword.json"
$EncryptedMasterPassword = ""
$Passwords = @{}

# Check if the master password file exists, if not create it and prompt the user for a new master password

if (!(Test-Path $MasterPasswordFile)) {
    $EncryptedMasterPassword = Encrypt-String -PlainText ([Convert]::ToBase64String($MasterPassword.GetBuffer())) -Password "MyPassword"
    $EncryptedMasterPassword | Out-File $MasterPasswordFile
}
else {
    $EncryptedMasterPassword = Get-Content $MasterPasswordFile
}

# Decrypt the master password and prompt the user if the password is incorrect

$DecryptedMasterPassword = Decrypt-String -EncryptedText $EncryptedMasterPassword -Password "MyPassword"
while ($MasterPassword.GetNetworkCredential().Password -ne $DecryptedMasterPassword) {
    Write-Host "Incorrect password"
    $MasterPassword = Read-Host "Enter the master password" -AsSecureString
}

# Decrypt the password file and display

$PasswordFile = "C:\PasswordManager\Passwords.json"
if (Test-Path $PasswordFile) {
    $EncryptedPasswords = Get-Content $PasswordFile
    $Passwords = ConvertFrom-Json -InputObject (Decrypt-String -EncryptedText $EncryptedPasswords -Password $MasterPassword.GetNetworkCredential().Password)
}

# Show the main menu

Show-MainMenu -MasterPasswordFile $MasterPasswordFile -PasswordFile $PasswordFile

# Encrypt and save the password file

$EncryptedPasswords = Encrypt-String -PlainText (ConvertTo-Json $Passwords) -Password $MasterPassword.GetNetworkCredential().Password
$EncryptedPasswords | Out-File $PasswordFile

Write-Host "Goodbye!"
