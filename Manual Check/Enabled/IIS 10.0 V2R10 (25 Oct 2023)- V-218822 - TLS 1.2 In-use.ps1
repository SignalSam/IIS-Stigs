# STIG Check Information
<#
Group Title:
    SRG-APP-000439-WSR-000156

Rule Title:
    The IIS 10.0 web server must maintain the confidentiality of controlled
    information during transmission through the use of an approved Transport
    Layer Security (TLS) version.

Discussion:
    TLS is a required transmission protocol for a web server hosting controlled
    information. The use of TLS provides confidentiality of data in transit between
    the web server and client. FIPS 140-2-approved TLS versions must be enabled and
    non-FIPS-approved SSL versions must be disabled.

    NIST SP 800-52 defines the approved TLS versions for government applications.

Check Text:
    Review the web server documentation and deployed configuration to determine which version of TLS is being used.
    If the TLS version is not TLS 1.2 or higher, according to NIST SP 800-52, or if non-FIPS-approved algorithms are enabled, this is a finding.

Fix Text:
    Configure the web server to use an approved TLS version according to NIST SP 800-52 and to disable all non-approved versions.
#>


# Script Information
<#
This script checks and reports compliance of the following items listed in the relevant check:
* Check if TLS 1.2 is in use.
This check is done per server.

This script returns a true or false value representing compliance on the whole, any item failure
will result in the entire check being considered non-compliant.

This script makes no changes to any configuration or settings.
#>


Set-PSDebug -Strict
$ErrorActionPreference = 'Stop'

# Script variable to track overall compliance.
[Boolean] $CheckCompliant = $True

Try
{
    If ((Invoke-WebRequest -Uri 127.0.0.1 -UseBasicParsing).StatusDescription -EQ 'OK')
        { $CheckCompliant = $False }
}
Catch
    {  }

Write-Output $CheckCompliant