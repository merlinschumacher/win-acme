<#
.SYNOPSIS
Imports a cert with a given thumbprint into SQL Server and sets the necessary permissions on the private key file.

.DESCRIPTION
This script imports a certificate with a given thumbprint into SQL Server and sets the necessary permissions on the private key file. 

The script is intended to be run via the install script plugin from win-acme via the batch script wrapper. As such, we use positional parameters to avoid issues with using a dash in the cmd line.

When you set up win-acme via the TUI make sure to set the script parameter value to '{CertThumbprint}' including the single quotes.

.LINK 
https://github.com/win-acme/win-acme 

.PARAMETER NewCertThumbprint
The thumbprint of the cert to be imported.

.EXAMPLE 
./ImportSQL.ps1 <certThumbprint>

This will import the cert with the given thumbprint into SQL Server.

.EXAMPLE
./wacs.exe --target manual --host hostname.example.com --installation script --script ".\Scripts\ImportSQL.ps1" --scriptparameters "'{CertThumbprint}'" --certificatestore My --acl-read "NT Service\MSSQLSERVER"

This is an example of how to use the script with win-acme. The script parameters should be set to '{CertThumbprint}' including the single quotes.

.NOTES
Inspired by 
https://blogs.infosupport.com/configuring-sql-server-encrypted-connections-using-powershell/ 
https://blog.wicktech.net/update-sql-ssl-certs/
#>

param(
    [Parameter(Position = 0, Mandatory = $true)]
    [string]$NewCertThumbprint
)

# Stop the script on any error
$ErrorActionPreference = 'Stop'

# Trim any whitespace from the thumbprint
$NewCertThumbprint = $NewCertThumbprint.Trim()

function Set-CertificatePermission {
    param($certificate)
   
    # Get the path to the private key file
    $containerName = $certificate.PrivateKey.CspKeyContainerInfo.UniqueKeyContainerName
    $path = Get-ChildItem -Path $env:AllUsersProfile\Microsoft\Crypto -Recurse -Filter $containerName | Select-Object -Expand FullName
    
    # Get the SQL service account
    $sqlServiceAccount = (Get-WmiObject win32_service -Filter "Name='MSSQLSERVER'").StartName
    
    # Grant the SQL service account read access to the private key file
    $currentAcl = Get-Acl -Path $path
    $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($sqlServiceAccount, "Read", "Allow")
    $currentAcl.AddAccessRule($accessRule)
    
    # Set the new ACL
    Set-Acl -Path $path -AclObject $currentAcl
}

function Set-SQLCertificate {
    param($NewCertThumbprint)
    
    # Locate the "SuperSocketNetLib" registry key that contains the encryption settings; highest 
    # first in case there are multiple versions.
    $regKey = Get-ChildItem "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Microsoft SQL Server" -Recurse | 
    Where-Object { $_.Name -like '*SuperSocketNetLib' } | 
    Sort-Object -Property Name -Descending
    
    if ($regKey.Count -gt 1) {
        $regKey = $regKey[0]
        Write-Warning "Multiple SQL instances found in the registry, using ""$($regKey.Name)""."
    }
    
    # The thumbprint must be in all lowercase, otherwise SQL server doesn't seem to accept it
    Set-ItemProperty -Path $regKey.PSPath -Name "Certificate" -Value $NewCertThumbprint.ToLowerInvariant()
}

# Check if the certificate exists in the store
$CertInStore = Get-ChildItem -Path Cert:\LocalMachine -Recurse | 
Where-Object { $_.thumbprint -eq $NewCertThumbprint } | 
Sort-Object -Descending | 
Select-Object -First 1

if (!$CertInStore) {
    Write-Error "The given cert thumbprint $NewCertThumbprint was not found in the cert store. Check the thumbprint and certificate storage and try again."
}

Write-Output "The following certificate was found in the store: $($CertInStore.FriendlyName)"

# Try to set the certificate in SQL server configuration
try {
    Set-SQLCertificate $NewCertThumbprint
    Write-Output "SQL server configuration was updated"
}
catch {
    Write-Error "The SQL server configuration was not set successfully: $_ $_.ScriptStackTrace"
}

# Try to set the ACL for the certificate
try {
    Set-CertificatePermission $CertInStore
    Write-Output "The ACL for the certificate was updated"
}
catch {
    Write-Error "Error updating ACL: $_ $_.ScriptStackTrace"
    Exit
}

# Restart the SQL service
try {
    Restart-Service -Name MSSQLSERVER -Force -ErrorAction Stop
}
catch {
    Write-Error "Error while restarting the SQL server: $_ $_.ScriptStackTrace"
}
