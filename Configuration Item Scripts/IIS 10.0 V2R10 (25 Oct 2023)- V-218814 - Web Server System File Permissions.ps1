# STIG Check Information
<#
Group Title:
    SRG-APP-000340-WSR-000029

Rule Title:
    IIS 10.0 web server system files must conform to minimum file permission requirements.

Discussion:
    This check verifies the key web server system configuration files are owned by the SA
    or the web administrator controlled account. These same files that control the
    configuration of the web server, and thus its behavior, must also be accessible by the
    account running the web service. If these files are altered by a malicious user, the web
    server would no longer be under the control of its managers and owners; properties in
    the web server configuration could be altered to compromise the entire server platform.

Check Text:
    Open Explorer and navigate to the inetpub directory.
    Right-click "inetpub" and select "Properties".
    Click the "Security" tab.
    Verify the permissions for the following users; if the permissions are less restrictive, this is a finding.
        System: Full control
        Administrators: Full control
        TrustedInstaller: Full control
        ALL APPLICATION PACKAGES (built-in security group): Read and execute
        ALL RESTRICTED APPLICATION PACKAGES (built-in security group): Read and execute
        Users: Read and execute, list folder contents
        CREATOR OWNER: Full Control, Subfolders and files only

Fix Text:
    Open Explorer and navigate to the inetpub directory.
    Right-click "inetpub" and select "Properties".
    Click the "Security" tab.
    Set the following permissions: 
        SYSTEM: Full control
        Administrators: Full control
        TrustedInstaller: Full control
        ALL APPLICATION PACKAGES (built-in security group): Read and execute
        Users: Read and execute, list folder contents
        CREATOR OWNER: special permissions to subkeys
#>


# Script Information
<#
This script checks and reports compliance of the following items listed in the relevant check:
* Checks if "IIS > Error Pages> Feature Settings..." is set to "Detailed errors for local requests and custom error pages for remote requests" or "Custom error pages".
This check is done per server.

This script returns a true or false value representing compliance on the whole, any item failure
will result in the entire check being considered non-compliant.

This script makes no changes to any configuration or settings.
#>


Function Get-IISSiteRootDirectoryAccess
{
    [CmdletBinding()]
    Param ([Parameter(Mandatory=$True)][Alias('N')][String] $Path)

    # Function variable to track discovery of unexpected rule.
    [Boolean] $UnexpectedRuleFound = $False

    # Functionvariabes to hold information.
    [System.Security.AccessControl.AuthorizationRuleCollection] $RootACLRules = (Get-Acl -Path $Path).Access

    # Function variables to setup access entries.
    [System.Security.Principal.NTAccount] $System = 'NT AUTHORITY\SYSTEM'
    [System.Security.Principal.NTAccount] $Administrators = 'BUILTIN\Administrators'
    [System.Security.Principal.NTAccount] $TrustedInstaller = 'NT SERVICE\TrustedInstaller'
    [System.Security.Principal.NTAccount] $AllApplicationPackages = 'APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES'
    [System.Security.Principal.NTAccount] $AllRestrictedApplicationPackages = 'APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES'
    # Typedef isn't needed for checking.
    #[System.Security.Principal.SecurityIdentifier] $AllRestrictedApplicationPackages = `
    #    [Security.Principal.NTAccount]::new('ALL RESTRICTED APPLICATION PACKAGES').Translate([System.Security.Principal.SecurityIdentifier])
    [System.Security.Principal.NTAccount] $Users = 'BUILTIN\Users'
    [System.Security.Principal.NTAccount] $CreatorOwner = 'CREATOR OWNER'
    [System.Security.AccessControl.FileSystemRights] $FullControl = [System.Security.AccessControl.FileSystemRights]::FullControl
    [System.Security.AccessControl.FileSystemRights] $ReadAndExecute = [System.Security.AccessControl.FileSystemRights]::ReadAndExecute
    # Synchronize is being automatically added to ReadAndExecute.
    #[System.Security.AccessControl.FileSystemRights] $ReadExecuteSynchronize = `
    #    [System.Security.AccessControl.FileSystemRights]::ReadAndExecute + [System.Security.AccessControl.FileSystemRights]::Synchronize
    [System.Security.AccessControl.AccessControlType] $Allow = [System.Security.AccessControl.AccessControlType]::Allow
    [System.Security.AccessControl.InheritanceFlags] $InheritAll = `
        [System.Security.AccessControl.InheritanceFlags]::ContainerInherit + [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    [System.Security.AccessControl.PropagationFlags] $PropNone = [System.Security.AccessControl.PropagationFlags]::None
    [System.Security.AccessControl.PropagationFlags] $PropInheretOnly = [System.Security.AccessControl.PropagationFlags]::InheritOnly

    [System.Collections.Generic.List[System.Security.AccessControl.FileSystemAccessRule]] $ExpectedRules = @()
        $ExpectedRules.Add((New-Object System.Security.AccessControl.FileSystemAccessRule($System, $FullControl, $InheritAll, $PropNone, $Allow)))
        $ExpectedRules.Add((New-Object System.Security.AccessControl.FileSystemAccessRule($Administrators, $FullControl, $InheritAll, $PropNone, $Allow)))
        $ExpectedRules.Add((New-Object System.Security.AccessControl.FileSystemAccessRule($TrustedInstaller, $FullControl, $InheritAll, $PropNone, $Allow)))
        $ExpectedRules.Add((New-Object System.Security.AccessControl.FileSystemAccessRule($AllApplicationPackages, $ReadAndExecute, $InheritAll, $PropNone, $Allow)))
        $ExpectedRules.Add((New-Object System.Security.AccessControl.FileSystemAccessRule($AllRestrictedApplicationPackages, $ReadAndExecute, $InheritAll, $PropNone, $Allow)))
        $ExpectedRules.Add((New-Object System.Security.AccessControl.FileSystemAccessRule($Users, $ReadAndExecute, $InheritAll, $PropNone, $Allow)))
        $ExpectedRules.Add((New-Object System.Security.AccessControl.FileSystemAccessRule($CreatorOwner, $FullControl, $InheritAll, $PropInheretOnly, $Allow)))
   
    ForEach ($RootACLRule In $RootACLRules)
    {
        [Boolean] $MatchesExpectedRule = $False
        ForEach ($Rule In $ExpectedRules)
        {
            If ($Null -EQ (Compare-Object -ReferenceObject $Rule -DifferenceObject $RootACLRule -Property FileSystemRights, AccessControlType, IdentityReference, InheritanceFlags, PropagationFlags))
                { $MatchesExpectedRule = $True }
        }

        If (-NOT $MatchesExpectedRule)
            { $UnexpectedRuleFound = $True }
    }

    If (-NOT $UnexpectedRuleFound)
        { Return $True }
    Else
        { Return $False }
}

Set-PSDebug -Strict
$ErrorActionPreference = 'Stop'

# Script variable to track overall compliance.
[Boolean] $CheckCompliant = $True

Try
{
    [System.Collections.Generic.List[Microsoft.IIs.PowerShell.Framework.ConfigurationElement]] $IISSites = Get-Website

    ForEach ($IISSite In $IISSites)
    {
        [String] $RootPath = (([System.IO.DirectoryInfo] [System.Environment]::ExpandEnvironmentVariables($IISSite.PhysicalPath)).Parent).Fullname
        If (-NOT (Get-IISSiteRootDirectoryAccess -Path $RootPath))
            { $CheckCompliant = $False }
    }
}
Catch
    { write-host 'ouch'}#$Host.SetShouldExit(1) }

Write-Output $CheckCompliant