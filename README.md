# LetsEncrypt_Az_AADDS_Renewal
Use to update LDAPS certificate with LetsEncrypt certificate automatically.


### DESCRIPTION
- Use this script to automatically and apply a LetsEncrypt certificate to Azure Active Directory Domain Services (AADDS).
- This should be run on a bi-weekly or monthly basis and will enable LDAPS and external access for LDAPS.
- This script requires the Posh-ACME module. Be sure to install the module.
- This script is currently designed to be run as an Azure Automation Runbook.
### PARAMETER LEserver
- Set this to `LE_STAGE` for testing
- Set this to `LE_PROD` for production
### PARAMETER domain
- Set this to the FQDN for AADDS - `ad.contoso.com`
- Don't specify anything other than the FQDN of the domain.
- Wildcard certificate will be issued for this domain but is handled by the script.
### PARAMETER contact
- Set this to the contact email for certificate related notifications
### PARAMETER dnsProvider
- Set this to `Azure`, `Cloudflare`, or `GoDaddy`
- This can support other providers but the script should be extended appropriately
- Azure will require the context this script is run under to have permission to modify the DNS Zone.
- dnsApiId and dnsApiSecret don't need to be set in this case.
- Cloudflare only supports Global API key as the API token feature appears to be broken on Cloudflare
- GoDaddy only has an option to create a key/secret
### PARAMETER dnsApiId
- Azure - set nothing here
- Cloudflare - Cloudflare account email here
- GoDaddy - API key here
### PARAMETER dnsApiSecret
- Azure - set nothing here
- Cloudflare - Cloudflare API secret here
- GoDaddy - API secret here
### PARAMETER externalAccess
- Set to `Enabled` or `Disabled` to enable secure LDAP access over the internet
