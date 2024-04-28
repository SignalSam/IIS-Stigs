# STIG Check Information
<#
Group Title:
    SRG-APP-000206-WSR-000128

Rule Title:
    Java software installed on a production IIS 10.0 web server must be limited to .class files
    and the Java Virtual Machine.

Discussion:
    Mobile code in hosted applications allows the developer to add functionality and displays to
    hosted applications that are fluid, as opposed to a static web page. The data presentation
    becomes more appealing to the user, is easier to analyze, and is less complicated to navigate
    through the hosted application and data.

    Some mobile code technologies in use in today's applications are: Java, JavaScript, ActiveX, PDF,
    Postscript, Shockwave movies, Flash animations, and VBScript. The DoD has created policies that
    define the usage of mobile code on DoD systems. The usage restrictions and implementation guidance
    apply to both the selection and use of mobile code installed on organizational servers and mobile
    code downloaded and executed on individual workstations.

    Source code for a Java program is often stored in files with either .java or .jpp file extensions.
    From the .java and .jpp files the Java compiler produces a binary file with an extension of .class.
    The .java or .jpp file could therefore reveal sensitive information regarding an application's logic
    and permissions to resources on the server.

Check Text:
    Search the system for files with either .java or .jpp extensions.
    If files with .java or .jpp extensions are found, this is a finding.

Fix Text:
    Remove all files from the web server with both .java and .jpp extensions.
#>


# Script Information
<#
This script checks and reports compliance of the following items listed in the relevant check:
* Checks all NTFS/ReFS fixed drives for .java or .jpp files.
This check is done per server.

This script may take an amount of time longer than the script timeout setting, check this link for
configuring longer timeout values for compliance items:
https://learn.microsoft.com/en-us/mem/configmgr/core/get-started/2022/technical-preview-2205#bkmk_timeout

If you need a value larger than the maximum 600 seconds availible, speak to Microsoft about manually setting it.

This script returns a true or false value representing compliance on the whole, any item failure
will result in the entire check being considered non-compliant.

This script makes no changes to any configuration or settings.
#>


Set-PSDebug -Strict
$ErrorActionPreference = 'Stop'

# Script variable to track overall compliance.
[Boolean] $CheckCompliant = $True

# Script variable to store volumes.
[System.Collections.Generic.List[CIMInstance]] $FixedVolumes = Get-Volume | Where-Object `
    { (($_.DriveType -EQ 'Fixed') -AND (($_.FileSystemType -EQ 'NTFS') -OR ($_.FileSystemType -EQ 'ReFS'))) }

ForEach ($FixedVolume In $FixedVolumes)
    {
        $ErrorActionPreference = 'Stop'
        Try
        {
            [System.Collections.Generic.List[System.IO.FileInfo]] $UnwantedFiles = Get-ChildItem -Path "$($FixedVolume.DriveLetter):\" -Include ('*.java', '*.jpp') -Recurse
            If ($UnwantedFiles.Count -GT 0)
            {
                $CheckCompliant = $False

                # Uncomment the code below if you run this manually and want the full path of the all the unwanted files.
                #Write-Host 'Found the following unwanted files:'
                #ForEach ($UnwantedFile In $UnwantedFiles)
                #    { $UnwantedFile.FullName }
            }        
        }
        Catch
            {  }
        $ErrorActionPreference = 'Continue'
    }

Write-Output $CheckCompliant