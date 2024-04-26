# STIG Check Information
<#
Group Title:
    SRG-APP-000100-WSR-000064

Rule Title:
    The IIS 10.0 web server must produce log records containing sufficient information
    to establish the identity of any user/subject or process associated with an event.

Discussion:
Web server logging capability is critical for accurate forensic analysis. Without sufficient
and accurate information, a correct replay of the events cannot be determined.

Determining user accounts, processes running on behalf of the user, and running process identifiers
also enable a better understanding of the overall event. User tool identification is also helpful to
determine if events are related to overall user access or specific client tools.

    Log record content that may be necessary to satisfy the requirement of this control includes:
        time stamps, source and destination addresses, user/process identifiers, event descriptions,
        success/fail indications, file names involved, and access control or flow control rules invoked.

Check Text:
    Access the IIS 10.0 web server IIS Manager.
    Click the IIS 10.0 web server name.
    Under "IIS", double-click the "Logging" icon.
    Verify the "Format:" under "Log File" is configured to "W3C".
    Select the "Fields" button.

    Under "Standard Fields", verify "User Agent", "User Name", and "Referrer" are selected.
    Under "Custom Fields", verify the following field has been configured:
    Request Header >> Authorization
    Response Header >> Content-Type
    If any of the above fields are not selected, this is a finding.

Fix Text:
    Access the IIS 10.0 web server IIS Manager.
    Click the IIS 10.0 web server name.
    Under "IIS", double-click the "Logging" icon.
    Verify the "Format:" under "Log File" is configured to "W3C".
    Select the "Fields" button.

    Under "Standard Fields", select "User Agent", "User Name", and "Referrer".
    Under "Custom Fields", select the following fields:
    Click on the "Source Type" drop-down list and select "Request Header".
    Click on the "Source" drop-down list and select "Authorization".
    Click "OK" to add.

    Click on the "Source" drop-down list and select "Content-Type".
    Click on the "Source Type" drop-down list and select "Response Header".
    Click "OK" to add.
    Click "OK".
    Click "Apply" under the "Actions" pane.
#>


# Script Information
<#
This script checks and reports compliance of the following items listed in the relevant check:
* Log format for each website on the server is set to "W3C".
* The minimum required logging fields are enabled.
* Existence of 2 custom log fields configured as defined in the STIG check. Log field display names
are not factored, extra custom fields are ignored.

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
        # User Agent = UserAgent
        $RequiredFields.Add('UserAgent')
        # User Name = UserName
        $RequiredFields.Add('UserName')
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

Function Get-IISLogCustomFields
{
    [CmdletBinding()]
    Param ([Parameter(Mandatory=$True)][Alias('N')][String] $Name)

    # Function variables to track detection of required custom fields.
    [Boolean] $RequestHeaderAuthorizationFound = $False
    [Boolean] $ResponseHeaderContentTypeFound = $False

    # Function variables to set the field attributes you require.
    [String] $FieldSourceTypeRequestHeader = 'RequestHeader'
    [String] $FieldSourceTypeResponseHeader = 'ResponseHeader'
    [String] $FieldSourceNameAuthorization = 'Authorization'
    [String] $FieldSourceNameContentType = 'Content-Type'

    [System.Collections.Generic.List[Microsoft.IIs.PowerShell.Framework.ConfigurationElement]] $CustomFields = (Get-ItemProperty "IIS:\sites\$Name" -Name 'logFile').customFields.Collection

    ForEach ($CustomField In $CustomFields)
    {
        If (($CustomField.sourceName -EQ $FieldSourceNameAuthorization) -AND ($CustomField.sourceType -EQ $FieldSourceTypeRequestHeader))
            { $RequestHeaderAuthorizationFound = $True }

        If (($CustomField.sourceName -EQ $FieldSourceNameContentType) -AND ($CustomField.sourceType -EQ $FieldSourceTypeResponseHeader))
            { $ResponseHeaderContentTypeFound = $True }    
    }

    If ($RequestHeaderAuthorizationFound -AND $ResponseHeaderContentTypeFound)
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

        If (-NOT (Get-IISLoggingFields -Name $IISSite.Name))
            { $CheckCompliant = $False }
    }
}
Catch
    { $Host.SetShouldExit(1) }

Write-Output $CheckCompliant