# Powershell-Password-manager

The script contains several functions:

    Encrypt-String: Encrypts a string using a password.
    Decrypt-String: Decrypts an encrypted string using a password.
    Set-MasterPassword: Creates or updates the encrypted master password file.
    Get-MasterPassword: Retrieves the master password from the encrypted file.
    Add-Password: Adds a password to the password file.
    Get-Password: Retrieves a password from the password file.

The script accepts two parameters:

    PasswordFile: The path to the password file. If the file does not exist, it will be created.
    MasterPasswordFile: The path to the file containing the encrypted master password. If the file does not exist, it will be created.

To use the script, run it with the -PasswordFile and -MasterPasswordFile parameters to specify the location of the password and master password files. The first time the script is run, it will prompt you to set a new master password. To add a password, run the Add-Password function, which will prompt you for the service name, username, and password. To retrieve a password, run the Get-Password function, which will prompt you for the service name and username and then display the password.
