# STIG Check Information
<#
Group Title:
    SRG-APP-000092-WSR-000055

Rule Title:
    Both the log file and Event Tracing for Windows (ETW) for the IIS 10.0 web server must be enabled.

Discussion:
    Internet Information Services (IIS) on Windows Server 2012 provides basic logging capabilities.
    However, because IIS takes some time to flush logs to disk, administrators do not have access to
    logging information in real-time. In addition, text-based log files can be difficult and time-consuming
    to process.

    In IIS 10.0, the administrator has the option of sending logging information to Event Tracing for Windows
    (ETW). This option gives the administrator the ability to use standard query tools, or create custom tools,
    for viewing real-time logging information in ETW. This provides a significant advantage over parsing
    text-based log files that are not updated in real time.

Satisfies:
    SRG-APP-000092-WSR-000055, SRG-APP-000108-WSR-000166, SRG-APP-000358-WSR-000063

Check Text:
    Open the IIS 10.0 Manager.
    Click the IIS 10.0 server name.
    Click the "Logging" icon.

    Under Log Event Destination, verify the "Both log file and ETW event" radio button is selected.
    If the "Both log file and ETW event" radio button is not selected, this is a finding.

Fix Text:
    Open the IIS 10.0 Manager.
    Click the IIS 10.0 server name.
    Click the "Logging" icon.

    Under Log Event Destination, select the "Both log file and ETW event" radio button.
    
    Under the "Actions" pane, click "Apply".
#>


# Script Information
<#
This script checks and reports compliance of the following items listed in the relevant check:
* Log event destination for each website on the server is set to "File,ETW".

This script returns a true or false value representing compliance on the whole, any item failure
will result in the entire check being considered non-compliant.

This script makes no changes to any configuration or settings.
#>

Function Get-IISLogEventDestination
{
    [CmdletBinding()]
    Param ([Parameter(Mandatory=$True)][Alias('N')][String] $Name)

    # Function variable to set the log destination you require.
    [String] $RequiredTarget = 'File,ETW'

    If ((Get-ItemProperty "IIS:\sites\$Name" -Name 'logFile').logTargetW3C -EQ $RequiredTarget)
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
        If (-NOT (Get-IISLogEventDestination -Name $IISSite.Name))
            { $CheckCompliant = $False }
    }
}
Catch
    { $Host.SetShouldExit(1) }

Write-Output $CheckCompliant