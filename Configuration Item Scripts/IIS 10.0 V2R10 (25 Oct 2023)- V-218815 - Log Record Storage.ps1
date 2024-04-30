# STIG Check Information
<#
Group Title:
    SRG-APP-000357-WSR-000150

Rule Title:
    The IIS 10.0 web server must use a logging mechanism configured to allocate log
    record storage capacity large enough to accommodate the logging requirements of
    the IIS 10.0 web server.

Discussion:
    To ensure the logging mechanism used by the web server has sufficient storage capacity
    in which to write the logs, the logging mechanism must be able to allocate log
    record storage capacity.

    The task of allocating log record storage capacity is usually performed during initial
    installation of the logging mechanism. The system administrator will usually coordinate
    the allocation of physical drive space with the web server administrator along with the
    physical location of the partition and disk. Refer to NIST SP 800-92 for specific
    requirements on log rotation and storage dependent on the impact of the web server.

Check Text:
    Open the IIS 10.0 Manager.
    Click the IIS 10.0 web server name.
    Under "IIS" double-click the "Logging" icon.
    In the "Logging" configuration box, determine the "Directory:" to which the "W3C" logging is being written.
    Confirm with the System Administrator that the designated log path is of sufficient size to maintain the logging.
    Under "Log File Rollover", verify "Do not create new log files" is not selected.
    Verify a schedule is configured to rollover log files on a regular basis.
    
    Consult with the System Administrator to determine if there is a documented process for moving the log files off of the IIS 10.0 web server to another logging device.
    If the designated logging path device is not of sufficient space to maintain all log files, and there is not a schedule to rollover files on a regular basis, this is a finding.

Fix Text:
    Open the IIS 10.0 Manager.
    Click the IIS 10.0 web server name.
    Under "IIS" double-click on the "Logging" icon.
    If necessary, in the "Logging" configuration box, re-designate a log path to a location able to house the logs.
    Under "Log File Rollover", de-select the "Do not create new log files" setting.
    Configure a schedule to rollover log files on a regular basis.
#>


# Script Information
<#
This script checks and reports compliance of the following items listed in the relevant check:
* Checks if there is X amount of free space on the volume used for logging (user-defined amount).
* Checks if scheduled log file rollovers are enabled.
This check is done per site.

This script returns a true or false value representing compliance on the whole, any item failure
will result in the entire check being considered non-compliant.

This script makes no changes to any configuration or settings.
#>


Function Get-IISSiteRootFreeSpace
{
    [CmdletBinding()]
    Param ([Parameter(Mandatory=$True)][Alias('D')][Char] $Drive)

   # Function variable to set minimum free space in GB.
    [Double] $MinimumFreeSpaceInGB = 100

    If (([Math]::Round((Get-PSDrive -Name $Drive).Free / 1GB)) -GE $MinimumFreeSpaceInGB)
        { Return $True }
    Else
        { Return $False }
}

Function Get-IISLogFileRollover
{
    [CmdletBinding()]
    Param ([Parameter(Mandatory=$True)][Alias('N')][String] $Name)

    If ((Get-ItemProperty "IIS:\sites\$Name" -Name 'logFile').period -NE 'MaxSize')
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
        [Char] $RootDrive = ([System.Environment]::ExpandEnvironmentVariables($IISSite.logFile.directory)).SubString(0, 1)
        If (-NOT (Get-IISSiteRootFreeSpace -Drive $RootDrive))
            { $CheckCompliant = $False }

        If (-NOT (Get-IISLogFileRollover -Name $IISSite.Name))
            { $CheckCompliant = $False }
    }
}
Catch
    { $Host.SetShouldExit(1) }

Write-Output $CheckCompliant