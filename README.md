Domain Controller Locator Script
Overview
This script is designed to locate the domain controller (DC) for user authentication by mimicking the DC locator process. It performs SRV DNS and LDAP queries to determine the DC and is intended for testing purposes only, not for production use.

Author
Ken Mei

Legal Disclaimer
This Sample Code is provided for the purpose of illustration only and is not intended to be used in a production environment. THIS SAMPLE CODE AND ANY RELATED INFORMATION ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE. We grant you a nonexclusive, royalty-free right to use and modify the Sample Code and to reproduce and distribute the object code form of the Sample Code, provided that you agree:

To not use our name, logo, or trademarks to market your software product in which the Sample Code is embedded.
To include a valid copyright notice on your software product in which the Sample Code is embedded.
To indemnify, hold harmless, and defend us and our suppliers from and against any claims or lawsuits, including attorneys’ fees, that arise or result from the use or distribution of the Sample Code.
Documentation
The script is based on documentation from:
https://learn.microsoft.com/en-us/archive/technet-wiki/24457.how-domain-controllers-are-located-in-windows
https://techcommunity.microsoft.com/blog/askds/domain-locator-across-a-forest-trust/395689

This script require you have portquery to be on the system, it's need to perform UDP port testing
you can download and extract it from the workstation then copy the .exe to the target machine to user.
https://download.microsoft.com/download/0/d/9/0d9d81cf-4ef2-4aa5-8cea-95a935ee09c9/PortQryV2.exe

Requirements
The script requires PortQry.exe for UDP port testing. You can download it from the An external link was removed to protect your privacy..

Usage
Input Parameters:

domainName: The user's domain (FQDN).
Username: The user's domain and username.
password: The user's password (entered as a secure string).
portquery_path: The path to PortQry.exe.
Functions:

check-server-port-status: Checks if the port is open and returns the DC name, IP, and status of UDP and TCP port 389.
get-sitename-subnet-info: Obtains site and subnet information for the specified domain.
get-subnetid: Converts IP/netmask into subnetID/netmask.
find-dc-site: Determines if a machine belongs to a site and finds its DC.
Process:

The script first checks if the domain name and PortQry.exe path are specified.
It then performs SRV DNS and LDAP queries to locate the DC.
If a site name match is found, it checks the status of UDP and TCP port 389 for the DC.
If no site name match is found, it explores all DCs in the domain and checks their port status.
The script also obtains AD site information and determines if the machine's IP address subnet matches any configured subnet/site.
Example
$domainName = Read-host "Users domain (FQDN)"
$Username = read-host "UserName (Domain\Username)"
$password = read-host "user's password: " -AsSecureString
[string]$portquery_path=".\PortQry.exe"

# Run the script
.\DomainControllerLocator.ps1
Notes
Ensure PortQry.exe is available on the system where the script is run.
This script is for testing purposes only and should not be used in a production environment.
