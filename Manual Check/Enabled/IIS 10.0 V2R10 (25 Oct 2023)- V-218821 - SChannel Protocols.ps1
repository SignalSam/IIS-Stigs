# STIG Check Information
<#
Group Title:
    SRG-APP-000439-WSR-000156

Rule Title:
    An IIS 10.0 web server must maintain the confidentiality of controlled information
    during transmission through the use of an approved Transport Layer Security (TLS) version.

Discussion:
    TLS encryption is a required security setting for a private web server. Encryption of
    private information is essential to ensuring data confidentiality. If private information
    is not encrypted, it can be intercepted and easily read by an unauthorized party. A private
    web server must use a FIPS 140-2-approved TLS version, and all non-FIPS-approved SSL
    versions must be disabled.

    NIST SP 800-52 specifies the preferred configurations for government systems.

Check Text:
    Access the IIS 10.0 Web Server.
    Navigate to:
        HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server
    Verify a REG_DWORD value of "0" for "DisabledByDefault".
    Verify a REG_DWORD value of "1" for "Enabled".

    Navigate to:
        HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server
        HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server
        HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server
        HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server

    Verify a REG_DWORD value of "1" for "DisabledByDefault".
    Verify a REG_DWORD value of "0" for "Enabled".

    If any of the respective registry paths do not exist or are configured with the wrong value, this is a finding.

Fix Text:
    Access the IIS 10.0 Web Server.
    Navigate to:
        HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server 
    Create a REG_DWORD named "DisabledByDefault" with a value of "0".
    Create a REG_DWORD named "Enabled" with a  value of "1".

    Navigate to:
        HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server
        HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server
        HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server
        HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server

    For each protocol:
        Create a REG_DWORD named "DisabledByDefault" with a value of "1".
        Create a REG_DWORD named "Enabled" with a  value of "0".
#>


# Script Information
<#
This script checks and reports compliance of the following items listed in the relevant check:
* Check if SCHANNEL keys/values in the registry are set as described in the check.
This check is done per server.

This script returns a true or false value representing compliance on the whole, any item failure
will result in the entire check being considered non-compliant.

This script makes no changes to any configuration or settings.
#>


Set-PSDebug -Strict
$ErrorActionPreference = 'Stop'

# Script variable to track overall compliance.
[Boolean] $CheckCompliant = $True

[String] $ProtocolPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols'
[String] $SSL20Path = "$ProtocolPath\SSL 2.0\Server"
[String] $SSL30Path = "$ProtocolPath\SSL 3.0\Server"
[String] $TLS10Path = "$ProtocolPath\TLS 1.0\Server"
[String] $TLS11Path = "$ProtocolPath\TLS 1.1\Server"
[String] $TLS12Path = "$ProtocolPath\TLS 1.2\Server"

If (-NOT((Test-Path -Path $SSL20Path) -AND (Test-Path -Path $SSL30Path) -AND (Test-Path -Path $TLS10Path) -AND `
    (Test-Path -Path $TLS11Path) -AND (Test-Path -Path $TLS12Path)))
    { $CheckCompliant = $False }
Else
{
    Try
    {
        If (((Get-ItemPropertyValue -Path $SSL20Path -Name Enabled) -EQ 1) -OR `
            ((Get-ItemPropertyValue -Path $SSL30Path -Name Enabled) -EQ 1) -OR `
            ((Get-ItemPropertyValue -Path $TLS10Path -Name Enabled) -EQ 1) -OR `
            ((Get-ItemPropertyValue -Path $TLS11Path -Name Enabled) -EQ 1) -OR `
            ((Get-ItemPropertyValue -Path $TLS12Path -Name Enabled) -EQ 0))
            { $CheckCompliant = $False }

        If (((Get-ItemPropertyValue -Path $SSL20Path -Name DisabledByDefault) -EQ 0) -OR `
            ((Get-ItemPropertyValue -Path $SSL30Path -Name DisabledByDefault) -EQ 0) -OR `
            ((Get-ItemPropertyValue -Path $TLS10Path -Name DisabledByDefault) -EQ 0) -OR `
            ((Get-ItemPropertyValue -Path $TLS11Path -Name DisabledByDefault) -EQ 0) -OR `
            ((Get-ItemPropertyValue -Path $TLS12Path -Name DisabledByDefault) -EQ 1))
            { $CheckCompliant = $False }
    }
    Catch
        { $CheckCompliant = $False }
}

Write-Output $CheckCompliant