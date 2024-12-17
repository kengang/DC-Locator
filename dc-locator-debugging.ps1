##########################################################################
#   Script to locate domain controller for user's authentication         #
# It's to troubleshoot and mimic the dc locator process to find the DC   #
# It perfome SRV DNS query and LDAP query to determine the DC            #
# It's only for testing purpose and not for production use               #
##########################################################################

<#     
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
$Username = read-host "UserName (Domain\Username)"
$password = read-host "user's password: " -AsSecureString
[string]$portquery_path=".\PortQry.exe"

#$password = Read-Host -Prompt "Enter your password" -AsSecureString
$script:plainTextPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($password))


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

#function to obtain site and subnet info
Function get-sitename-subnet-info {
  param (
    [string]$domainName,
    [string]$username,
    [string]$password
    )
    # Get the domain context
    $context = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("domain", "$domainName", $username, $password)

    # Get the domain object
    try{
    $domain = [System.DirectoryServices.ActiveDirectory.domain]::Getdomain($context)
    } catch{  
        Write-Host $_
        break
    } 
    # Get the sites in the domain
    $sites = $domain.Forest.Sites


    # Display detailed information for each site
    foreach ($site in $sites) {
        $siteInfo = @{
            Name = $site.Name
            Servers = $site.Servers
            Subnets = $site.Subnets
  
        }
        $siteInfo
    }
}

#function to covert IP/netmask into subnetID/netmask
Function get-subnetid {
    param(
      [string]$ip,
      [string]$prefixLength
    )

    function ipNr($s) {
        [byte[]]$ip = $s.Split(".")
        [array]::Reverse($ip)
        [bitconverter]::ToUInt32($ip,0)
    }

    function ipString($n) {
        $ip = [bitconverter]::GetBytes($n)
        [array]::Reverse($ip)
        [string]::Join(".", $ip)
    }

    function maskNr($b) {
        (1 -shl $b)-1 -shl (32-$b)
    }

    $subnetId = ipString ((ipNr $ip) -band (maskNr $prefixLength)) 
   return "$subnetId/$prefixLength"


}

#function to determine if machine below to an site and find its DC
Function find-dc-site{
  param(
    [array]$sites,
    [string]$subnetid
   )

   
foreach ($site in $sites) {

        if ($site.subnets.name -eq $subnetid) {
            return $site
            break
        }
}
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

        # get all AD site info from User's domain/forest
        $siteInfo = get-sitename-subnet-info -domainName $domainName -username $username -password $plainTextPassword
    
        #next two line determine the Machine IP networkId/Netmask
        $server_ip_info =Get-NetAdapter -Physical |where status -eq "UP" | Get-NetIPAddress -AddressFamily IPv4| select IPAddress, PrefixLength
        $subnetid = get-subnetid -ip $server_ip_info.IPAddress -prefixLength $server_ip_info.PrefixLength

        #check if machine's IP Address subnet matches any subnet/site configured in user's site/service
        $matched_site = find-dc-site -sites $siteInfo -subnetid $subnetid

        if ($matched_site -ne $null) {
          
          $DC_via_LDAP = @()
          foreach ($server in $matched_site.Servers) {
                
                    $dc_info = @{
                            SiteName = $server.SiteName
                            DCName = $server.Name
                            IPAddress = $server.IPAddress 
                            subnet = $matched_site.Subnets
                    }

                    $DC_via_LDAP += $dc_info
          }

          #get DC records from DNS, compare both result to ensue configuration accuracy
          $site = $matched_site.Name
          $sitequeryname = "_ldap._tcp.$site._sites.dc._msdcs.$domainName"  
          $dc_via_srv =(Resolve-DnsName -Type SRV  -name  $sitequeryname).nametarget

          $DC_via_DNS = @()
          foreach ($name in $dc_via_srv) {
                $ipaddr = (Resolve-DnsName -Type A -Name $name -ErrorAction SilentlyContinue).ipaddress

                 $dns_info = @{
                            Server= $Name
                            IPAddress = $ipaddr }
                $DC_via_DNS +=$dns_info
          }

          Write-host "****************************"
          write-host "****************************"
          write-host "You machine is belong to this Site $site via LDAP: " -ForegroundColor Green
          write-host ($DC_via_LDAP  |Format-Table |Out-String)
          Write-host "****************************"
          write-host "****************************"
          write-host "DC is located in this Site $site via DSN SVC record" -ForegroundColor Green
          Write-Host ($DC_via_DNS |Format-Table |Out-String)
          Write-host "****************************"
          write-host "****************************"
      
        } else {
            write-host " Your machine is not belong to any Site" -ForegroundColor Red
            Write-host "****************************"
            write-host "****************************"
        }
    } else{
            write-host "NO DC Found, please verify manually"
    }   

}
