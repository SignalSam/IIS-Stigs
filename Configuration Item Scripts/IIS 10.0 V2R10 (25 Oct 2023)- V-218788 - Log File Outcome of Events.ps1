# STIG Check Information
<#
Group Title:
    SRG-APP-000099-WSR-000061

Rule Title:
    The IIS 10.0 web server must produce log records that contain sufficient information to
    establish the outcome (success or failure) of IIS 10.0 web server events.

Discussion:
    Web server logging capability is critical for accurate forensic analysis. Without sufficient
    and accurate information, a correct replay of the events cannot be determined.

    Ascertaining the success or failure of an event is important during forensic analysis. Correctly
    determining the outcome will add information to the overall reconstruction of the loggable event.
    By determining the success or failure of the event correctly, analysis of the enterprise can be
    undertaken to determine if events tied to the event occurred in other areas within the enterprise.

    Without sufficient information establishing the success or failure of the logged event, investigation
    into the cause of event is severely hindered. The success or failure also provides a means to measure
    the impact of an event and help authorized personnel determine the appropriate response. Log record
    content that may be necessary to satisfy the requirement of this control includes, but is not limited
    to, time stamps, source and destination IP addresses, user/process identifiers, event descriptions,
    application-specific events, success/fail indications, file names involved, access control, or flow
    control rules invoked.

Check Text:
    Access the IIS 10.0 web server IIS Manager.
    Click the IIS 10.0 web server name.
    Under "IIS", double-click the "Logging" icon.
    Verify the "Format:" under "Log File" is configured to "W3C".
    Select the "Fields" button.
    Under "Custom Fields", verify the following fields have been configured:
    Request Header >> Connection
    Request Header >> Warning
    If any of the above fields are not selected, this is a finding.

Fix Text:
    Access the IIS 10.0 web server IIS Manager.
    Click the IIS 10.0 web server name.
    Under "IIS", double-click the "Logging" icon.
    Verify the "Format:" under "Log File" is configured to "W3C".
    Select the "Fields" button.
    Under "Custom Fields", click the "Add Field..." button.
    For each field being added, give a name unique to what the field is capturing.

    Click on the "Source Type" drop-down list and select "Request Header".
    Click on the "Source" drop-down list and select "Connection".
    Click "OK" to add.

    Click on the "Source Type" drop-down list and select "Request Header".
    Click on the "Source" drop-down list and select "Warning".
    Click "OK" to add.

    Click "Apply" under the "Actions" pane.
#>


# Script Information
<#
This script checks and reports compliance of the following items listed in the relevant check:
* Log format for each website on the server is set to "W3C".
* Existence of 2 custom log fields configured as defined in the STIG check. Log field display names
are not factored, extra custom fields are ignored.
These checks are done per site.

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

Function Get-IISLogCustomFields
{
    [CmdletBinding()]
    Param ([Parameter(Mandatory=$True)][Alias('N')][String] $Name)

    # Function variables to track detection of required custom fields.
    [Boolean] $RequestHeaderConnectionFound = $False
    [Boolean] $RequestHeaderWarningFound = $False

    # Function variables to set the field attributes you require.
    [String] $FieldSourceType = 'RequestHeader'
    [String] $FieldSourceNameConnection = 'Connection'
    [String] $FieldSourceNameWarning = 'Warning'

    [System.Collections.Generic.List[Microsoft.IIs.PowerShell.Framework.ConfigurationElement]] $CustomFields = (Get-ItemProperty "IIS:\sites\$Name" -Name 'logFile').customFields.Collection

    ForEach ($CustomField In $CustomFields)
    {
        If (($CustomField.sourceName -EQ $FieldSourceNameConnection) -AND ($CustomField.sourceType -EQ $FieldSourceType))
            { $RequestHeaderConnectionFound = $True }

        If (($CustomField.sourceName -EQ $FieldSourceNameWarning) -AND ($CustomField.sourceType -EQ $FieldSourceType))
            { $RequestHeaderWarningFound = $True }    
    }

    If ($RequestHeaderConnectionFound -AND $RequestHeaderWarningFound)
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

        If (-NOT (Get-IISLogCustomFields -Name $IISSite.Name))
            { $CheckCompliant = $False }
    }
}
Catch
    { $Host.SetShouldExit(1) }

Write-Output $CheckCompliant