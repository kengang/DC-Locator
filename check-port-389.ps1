<##########################################################################
Script to check if UDP and TCP port 389 is opened for the DC at the Server site,
if not it will check All DCs and their port status.

Author: Ken Mei

 LEGAL DISCLAIMER
This Sample Code is provided for the purpose of illustration only and is not
intended to be used in a production environment.  THIS SAMPLE CODE AND ANY
RELATED INFORMATION ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER
EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF
MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.  We grant You a
nonexclusive, royalty-free right to use and modify the Sample Code and to
reproduce and distribute the object code form of the Sample Code, provided
that You agree: (i) to not use Our name, logo, or trademarks to market Your
software product in which the Sample Code is embedded; (ii) to include a valid
copyright notice on Your software product in which the Sample Code is embedded;
and (iii) to indemnify, hold harmless, and defend Us and Our suppliers from and
against any claims or lawsuits, including attorneys’ fees, that arise or result
from the use or distribution of the Sample Code.
 

Documentation the script based on
https://learn.microsoft.com/en-us/archive/technet-wiki/24457.how-domain-controllers-are-located-in-windows
https://techcommunity.microsoft.com/blog/askds/domain-locator-across-a-forest-trust/395689

This script require you have portquery to be on the system, it's need to perform UDP port testing
you can download and extract it from the workstation then copy the .exe to the target machine to user.

https://download.microsoft.com/download/0/d/9/0d9d81cf-4ef2-4aa5-8cea-95a935ee09c9/PortQryV2.exe


#>


$domainName = Read-host "Users domain (FQDN)"
[string]$portquery_path=".\PortQry.exe"

$port = 389
$status = "UDP port 389 is LISTENING"


if (-not $domainName) {
  Write-Host "Please specify user's own domain name.com"
  break
} else {
  if (!(Get-Item -Path $portquery_path -ErrorAction SilentlyContinue)) {
   write-host "porqry.exe does not exist, please specify portqry.exe location"
   $portquery_path = read-host "enter valid path for PortQry.exe"
  }
}


# function to check if port is open, return DC name, IP, upd and tcp 389 status
Function check-server-port-status {
  param(
   [array]$servers,
   [int]$port =389

  )
  $dc_udp_status =@()
  foreach($rec in $srv_records) {

    $dc_ip = (Resolve-DnsName -Type A -Name $rec).ipaddress
    $query_result = &$portquery_path -n $dc_ip -e $port -p UDP

    if ($query_result[-2] -match $status){
        $status_udp = "Open"
    } else {
            $status_udp =  "Not Open"
    }
    
    if (Test-NetConnection -ComputerName $dc_ip -Port $port) {
            $status_tcp = "open"
    } else{
        $status_tcp = "not open"
    }
    
    # Create a new object
    $dcobj = New-Object PSObject -Property @{
             DCName = $rec
             IPAddress =  $dc_ip
             TCP_389 = $status_tcp
             UDP_389 = $status_udp
             }
    $dc_udp_status += $dcobj
 }
 return $dc_udp_status
}


#get the AD site for the machine where the script is running

$site = (& nltest /dsgetsite)[0] 2>$null


#domain wide query string for DC
$domainqueryname = "_ldap._tcp.dc._msdcs.$domainName"

#Site query string for DC
$sitequeryname = "_ldap._tcp.$site._sites.dc._msdcs.$domainName"

#Flush dns cache
&ipconfig /flushdns |Out-Null

# get SRV records for a particular site in the user's own domain
$srv_records = (Resolve-DnsName -Type SRV  -name  $sitequeryname -ErrorAction Ignore).nametarget


if ($srv_records -ne $null) { # there's site name match between trusted and trusting domain, and SRV record found
        #check DC 389 UDP and TCP status
        $results = check-server-port-status -servers $srv_records -port $port
        Write-host "Domain controllers are found at site $site in domain $domainName"
        write-host ($results |Format-Table |Out-String)
    
} else{ #No site Name match between trusted and trusting domain
    
    #get SRC records for the whole user domain
    $srv_records = (Resolve-DnsName -Type SRV  -name $domainqueryname -ErrorAction SilentlyContinue).nametarget
    
    #Check DC 389 UDP and TCP status
    $results = check-server-port-status -servers $srv_records -port $port

    write-host "--->>There's no DC found at Site $site in domain $domainName <<---" -ForegroundColor Red
    Write-host "****************************"
    write-host "****************************"
    write-host "--->>explore all the DC in the domain $domainName<<----" -ForegroundColor Green
    if ($results -ne $null) {
        Write-host "****************************"
        write-host "****************************"
        write-host "All DCs and its port stauts"
        write-host ($results |Format-Table |Out-String)

       
    } else{
            write-host "NO DC Found, please verify manually"
    }   

}
