# STIG Check Information
<#
Group Title:
    SRG-APP-000092-WSR-000055

Rule Title:
    The enhanced logging for the IIS 10.0 web server must be enabled and capture all user and web server events.

Discussion:
    Log files are a critical component to the successful management of an IS used within the DoD.
    By generating log files with useful information, web administrators can leverage them in the event of a disaster,
    malicious attack, or other site specific needs.

    Ascertaining the correct order of the events that occurred is important during forensic analysis. Events that appear
    harmless by themselves might be flagged as a potential threat when properly viewed in sequence. By also establishing the
    event date and time, an event can be properly viewed with an enterprise tool to fully see a possible threat in its entirety.

    Without sufficient information establishing when the log event occurred, investigation into the cause of event is severely hindered.
    Log record content that may be necessary to satisfy the requirement of this control includes, but is not limited to, time stamps,
    source and destination IP addresses, user/process identifiers, event descriptions, application-specific events, success/fail indications,
    file names involved, access control, or flow control rules invoked.

Satisfies:
    SRG-APP-000092-WSR-000055, SRG-APP-000093-WSR-000053, SRG-APP-000095-WSR-000056,
    SRG-APP-000096-WSR-000057, SRG-APP-000097-WSR-000058, SRG-APP-000097-WSR-000059

Check Text:
    Open the IIS 10.0 Manager.
    Click the IIS 10.0 web server name.
    Click the "Logging" icon.
    Under Format select "W3C".

    Click "Select Fields", verify at a minimum the following fields are checked:
    Date, Time, Client IP Address, User Name, Method, URI Query, Protocol Status, and Referrer.

    If not, this is a finding.

Fix Text:
    Open the IIS 10.0 Manager.
    Click the IIS 10.0 web server name.
    Click the "Logging" icon.
    Under Format select "W3C".

    Select the following fields:
        Date, Time, Client IP Address, User Name, Method, URI Query, Protocol Status, and Referrer.

    Under the "Actions" pane, click "Apply".
#>


# Script Information
<#
This script checks and reports compliance of the following items listed in the relevant check:
* Log format for each website on the server is set to "W3C".
* The minimum required logging fields are enabled.
This check is done per site.

This script returns a true or false value representing compliance on the whole, any item failure
will result in the entire check being considered non-compliant.

This script makes no changes to any configuration or settings.
#>

Function Get-IISLogFormat
{
    [CmdletBinding()]
    Param ([Parameter(Mandatory=$True)][Alias('N')][String] $Name)

    # Function variable to set the log type you require.
    [String] $RequiredFormat = 'W3C'

    If ((Get-ItemProperty "IIS:\sites\$Name" -Name 'logFile').logFormat -EQ $RequiredFormat)
        { Return $True }
    Else
        { Return $False }
}

Function Get-IISLoggingFields
{
    [CmdletBinding()]
    Param ([Parameter(Mandatory=$True)][Alias('N')][String] $Name)

    # Function varibe to track if a required field was not found.
    [Boolean] $RequiredFieldMissing = $False

    # List of the names of the required fields, these ARE case sensitive.
    # The STIG lists display names but they're stored is short name format.
    # The STIG also has a typo listing "referrer" when it is "referer".
    [System.Collections.Generic.List[String]] $RequiredFields = @()
        $RequiredFields.Add('Date')
        $RequiredFields.Add('Time')
        # Client IP Address = ClientIP
        $RequiredFields.Add('ClientIP')
        # User Name = UserName
        $RequiredFields.Add('UserName')
        $RequiredFields.Add('Method')
        # URI Query = UriQuery
        $RequiredFields.Add('UriQuery')
        # Protocol Staus = HttpStatus
        $RequiredFields.Add('HttpStatus')
        $RequiredFields.Add('Referer')

    [System.Collections.Generic.List[String]] $EnabledFields = ((Get-ItemProperty "IIS:\sites\$Name" -Name 'logfile').logExtFileFlags).Split(',')

    ForEach ($RequiredField In $RequiredFields)
    {
        If ($EnabledFields.IndexOf($RequiredField) -EQ -1)
            { $RequiredFieldMissing = $True }
    }

    If ($RequiredFieldMissing -EQ $False)
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
        If (-NOT (Get-IISLogFormat -Name $IISSite.Name))
            { $CheckCompliant = $False }

        If (-NOT (Get-IISLoggingFields -Name $IISSite.Name))
            { $CheckCompliant = $False }
    }
}
Catch
    { $Host.SetShouldExit(1) }

Write-Output $CheckCompliant