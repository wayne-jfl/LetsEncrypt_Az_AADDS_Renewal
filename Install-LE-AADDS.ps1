<#
.SYNOPSIS
    .
.DESCRIPTION
    Use this script to automatically and apply a LetsEncrypt certificate to Azure Active Directory Domain Services (AADDS).
    This should be run on a bi-weekly or monthly basis and will enable LDAPS and external access for LDAPS.
    This script requires the Posh-ACME module. Be sure to install the module.
    This script is currently designed to be run as an Azure Automation Runbook.
.PARAMETER LEserver
    Set this to LE_STAGE for testing
    Set this to LE_PROD for production
.PARAMETER domain
    Set this to the FQDN for AADDS - ad.contoso.com
    Don't specify anything other than the FQDN of the domain.
    Wildcard certificate will be issued for this domain but is handled by the script.
.PARAMETER contact
    Set this to the contact email for certificate related notifications
.PARAMETER dnsProvider
    Set this to Azure, Cloudflare, or GoDaddy
    This can support other providers but the script should be extended appropriately
    Azure will require the context this script is run under to have permission to modify the DNS Zone.
        dnsApiId and dnsApiSecret don't need to be set in this case.
    Cloudflare only supports Global API key as the API token feature appears to be broken on Cloudflare
    GoDaddy only has an option to create a key/secret
.PARAMETER dnsApiId
    Azure - set nothing here
    Cloudflare - Cloudflare account email here
    GoDaddy - API key here
.PARAMETER dnsApiSecret
    Azure - set nothing here
    Cloudflare - Cloudflare API secret here
    GoDaddy - API secret here
.NOTES
    Version:         0.1
    Author:          Zachary Choate
    Creation Date:   02/05/2020
    Source location: https://github.com/zchoate/LetsEncrypt_Az_AADDS_Renewal/Install-LE-AADDS.ps1
#>
param(
    [string] $LEserver,
    [string] $domain,
    [string] $contact,
    [string] $dnsProvider,
    [string] $dnsApiId,
    [string] $dnsApiSecret
)

# Pull from Automation variables if not passed through
If(-not $LEserver) {$LEserver = Get-AutomationVariable -Name 'LEserver'}
If(-not $domain) {$domain = Get-AutomationVariable -Name 'domain'}
If(-not $contact) {$contact = Get-AutomationVariable -Name 'contact'}
If(-not $dnsProvider) {$dnsProvider = Get-AutomationVariable -Name 'dnsProvider'}
If(-not $dnsApiId) {$dnsApiId = Get-AutomationVariable -Name 'dnsApiId'}
If(-not $dnsApiSecret) {$dnsApiSecret = Get-AutomationVariable -Name 'dnsApiSecret'}

$paServer = $LEserver
$wildcardDomain = "*.$domain"

If($dnsProvider = "GoDaddy") {
    $dnsArguments = @{GDKey=$dnsApiId;GDSecret=$dnsApiSecret}
} elseif ($dnsProvider = "Cloudflare") {
    $dnsArguments = @{CFAuthEmail=$dnsApiId;CFAuthKey=$dnsApiSecret}
} elseif ($dnsProvider = "Azure") {
    $dnsArguments = @{AZSubscriptionId=$context.Subscription.Id;AZAccessToken=$accessToken}
} else { Write-Output "There isn't a supported DNS provider selected. Please choose from Azure, Cloudflare, or GoDaddy. If you need another configured, please modify the script appropriately."}

## Check for Posh-ACME module
If(!(Get-Module -ListAvailable -Name "Posh-ACME")) {
    Write-Output "Install Posh-ACME module by running the command Install-Module Posh-ACME."
    Exit
} 

# Check for Az vs AzureRM modules
If(!(Get-Module -ListAvailable -Name "Az")) {
    Write-Output "Az modules are not installed, you may want to update this but in the meantime, we'll defer to AzureRM."
    $azModuleInstalled = $false
}

# Don't inherit Azure Context in runbook
If($azModuleInstalled) {
    Disable-AzContextAutosave -Scope Process
} else {
    Disable-AzureRmContextAutosave -Scope Process
}
$connection = Get-AutomationConnection -Name AzureRunAsConnection
while(!($connectionResult) -And ($logonAttempt -le 10))
{
    $LogonAttempt++
    # Logging in to Azure...
    If($azModuleInstalled) {
        $connectionResult = Connect-AzAccount -ServicePrincipal -Tenant $connection.TenantID -ApplicationID $connection.ApplicationID -CertificateThumbprint $connection.CertificateThumbprint
    } else {
        $connectionResult = Connect-AzureRmAccount -ServicePrincipal -Tenant $connection.TenantID -ApplicationID $connection.ApplicationID -CertificateThumbprint $connection.CertificateThumbprint
    }
    Start-Sleep -Seconds 30
}

## Import Posh-ACME module
Import-Module -Name Posh-ACME
# Set server (staging or prod)
Set-PAServer $paServer

# Get current account, update contact if account has been updated, or create a new account.
$acct = Get-PAAccount
If(-not $acct) {
    $acct = New-PAAccount -Contact $contact -KeyLength 4096 -AcceptTOS
} elseif ($acct.contact -ne "mailto:$contact") {
    Set-PAAccount -id $acct.id -Contact $contact
}

# See if there's been an order created
$paOrder = Get-PAOrder -MainDomain $wildcardDomain

If(-not $paOrder) {
    # Run request for new certificate
    $certificate = New-PACertificate $wildcardDomain,$domain -DnsPlugin $dnsProvider -PluginArgs $dnsArguments -AcceptTOS -Contact $contact -Verbose
} else {
    # Insert request for renewal of certificate
    Set-PAOrder -MainDomain $wildcardDomain -DnsPlugin $dnsProvider -PluginArgs $dnsArguments -Verbose
    $certificate = Submit-Renewal -Verbose
}

# Get Azure resource object for AADDS.
If($azModuleInstalled) {
    $aaddsResource = Get-AzResource -ResourceType "Microsoft.AAD/DomainServices"
} else {
    $aaddsResource = Get-AzureRMResource -ResourceType "Microsoft.AAD/DomainServices"
}


$currentOrder = Get-PAOrder -MainDomain $wildcardDomain
$pfxCertificate = [System.IO.File]::ReadAllBytes($certificate.PfxFile)
$pfxCertificate = [System.Convert]::ToBase64String($pfxCertificate)
$AADDSsettings = @(@{
    "properties" =
    @{
        "ldapsSettings" =
            @{
            "ldaps" = "Enabled"
            "externalAccess" = "Enabled"
            "certificateThumbprint" = $certificate.Thumbprint
            "certificateNotAfter" = $certificate.NotAfter
            "pfxCertificate" = $pfxCertificate
            "pfxCertificatePassword" = $currentOrder.PfxPass
        }
    }
})
$json = $AADDSsettings | ConvertTo-Json -Depth 10

# Get Azure context and bearer token.
If($azModuleInstalled) {
    $context = Get-AzContext
} else {
    $context = Get-AzureRMContext
}
$cache = $context.TokenCache
$cacheItem = $cache.ReadItems()
$accessToken=($cacheItem | Where-Object { $_.Resource -eq “https://management.core.windows.net/" })[0].AccessToken

# Initiate REST PATCH with new certificate information
$url = "https://management.azure.com" + $aaddsResource.ResourceId + "?api-version=2017-06-01"
$headerParams = @{"Authorization" = "Bearer $accessToken"}
Invoke-RestMethod -Uri $url -Headers $headerParams -Method Patch -ContentType 'application/json' -Body $json