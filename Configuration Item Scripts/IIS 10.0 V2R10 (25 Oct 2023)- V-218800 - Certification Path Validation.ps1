# STIG Check Information
<#
Group Title:
    SRG-APP-000175-WSR-000095

Rule Title:
    The IIS 10.0 web server must perform RFC 5280-compliant certification path validation.

Discussion:
    This check verifies the server certificate is actually a DoD-issued certificate used by
    the organization being reviewed. This is used to verify the authenticity of the website
    to the user. If the certificate is not issued by the DoD or if the certificate has expired,
    then there is no assurance the use of the certificate is valid, and therefore; the entire
    purpose of using a certificate is compromised.

Check Text:
    Open the IIS 10.0 Manager.
    Click the IIS 10.0 web server name.
    Double-click the "Server Certificate" icon.
    Double-click each certificate and verify the certificate path is to a DoD root CA.
    If the “Issued By” field of the PKI certificate being used by the IIS 10.0 server/site does not indicate the issuing Certificate Authority (CA) is part of the DoD PKI or an approved ECA, this is a finding.

Fix Text:
    Open the IIS 10.0 Manager.
    Click the IIS 10.0 web server name.
    Double-click the "Server Certificate" icon.

    Import a valid DoD certificate and remove any non-DoD certificates.
#>


# Script Information
<#
This script checks and reports compliance of the following items listed in the relevant check:
* Checks if certificates used in bindings match a defined list of known acceptable certificates.
Note: This script will also check to ensure at least one secure port binding exists.
This check is done per server.

This script returns a true or false value representing compliance on the whole, any item failure
will result in the entire check being considered non-compliant.

This script makes no changes to any configuration or settings.
#>

Function Compare-Thumbprint
{
    [CmdletBinding()]
    Param ([Parameter(Mandatory=$True)][Alias('T')][String] $Thumbprint)

    # Function variable to store expected known good thumbprints, and status.
    [System.Collections.Generic.List[String]] $GoodThumbprints = @()
    # Add as many lines as needed for each thumbprint, sample format is below.
        #$GoodThumbprints.Add('D5D0845A99EA8273C14684E300D43AC5F883D690')
        $GoodThumbprints.Add('')

    [Boolean] $MatchesKnownGood = $False

    ForEach ($GoodThumbprint In $GoodThumbprints)
    {
        If ($Thumbprint -EQ $GoodThumbprint)
            { $MatchesKnownGood = $True }
    }

    Return $MatchesKnownGood
}

Set-PSDebug -Strict
$ErrorActionPreference = 'Stop'

# Script variable to track overall compliance.
[Boolean] $CheckCompliant = $True

# Script variable to store bindings.
[System.Collections.Generic.List[PSObject]] $Bindings = Get-ChildItem -Path 'IIS:\SslBindings'

If ($Bindings.Count -EQ 0)
    { $CheckCompliant = $False }
Else
{
    ForEach ($Binding In $Bindings)
    {
        If ((Compare-Thumbprint -Thumbprint $Binding.Thumbprint) -NE $True)
            { $CheckCompliant = $False }
    }
}

Write-Output $CheckCompliant