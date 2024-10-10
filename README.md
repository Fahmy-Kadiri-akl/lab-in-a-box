# Akeyless-azure-lab
* A docker based Akeyless lab in Azure

## Pre-requisite
* Register for a free Akeyless account: console.akeyless.io
* Have an active Azure AD subscription: you will need this to create VM

## Nice-to-have
SAML / OIDC auth method: you'll use this for login to the UI and CLI access. --> https://docs.akeyless.io/docs/saml

## Steps
* have your azure login info ready
* have your Akeyless SAML and Gateway access-ids ready
* Clone the repo locally and run the azure install script

## Outcomes
* Creates an Azure VM with managed identity
* Creates Azure AD auth method:  you'll use this auth method to authenticate the akeyless gateway in your Azure VM to your account --> https://docs.akeyless.io/docs/azure-ad
* Creates Docker Containers: akeyless-gateway, Postgresql, Grafana, and custom-server.
* Custom-server will be used for creating dynamic / rotated secret objects for custom and non-supported applications e.g. Grafana
* Configures Akeyelss components: Gateway, Auth Methods, Access-Roles, Gateway Permissions
* Creates Secret items: Static, Encryption, Rotated, Dynamic-Read-only, and Dynamic-Super-User

## To Do
* Configure DFC / Customer Fragment
* SSH Cert issuer for Certificate based SSH access to Linux Machines
* Configure Linux container to use as SSH Target
* Configure Custom Producer for Grafana web server
* Configure Gateway metrics
* Configure Ingress
* Configure Automatic Migration?
* Configure Universal Secrets Connector (Azure Key Vault, Hashi, AWS, GCP, K8s)
* Configure Azure DevOps integration
* Convert to Azure Container services rather than running on VM
