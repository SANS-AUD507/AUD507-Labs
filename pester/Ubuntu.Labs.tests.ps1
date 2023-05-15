# Invoke this test in PWSH on 507Ubuntu with these commands:
<#
$config=New-PesterConfiguration
$config.Output.Verbosity='detailed'
$config.Run.Path = './Ubuntu.Labs.tests.ps1'
Invoke-Pester -Configuration $config
#>

Describe '507 Labs'{
  BeforeDiscovery {
    #If the AWS config files are not there, then skip the AWS tests
    if( -not ( (Test-Path -Type Leaf -Path /home/student/.aws/credentials) -or (Test-Path -Type Leaf -Path /home/student/.aws/config) ) ) {
      $skipAWS = $true
    }
    else {
      #Skip the Cloud Services tests if there are no good AWS credentials
      $userARN = (aws sts get-caller-identity | jq '.Arn')
      if( $userARN -notlike '*student*'){
        $skipAWS = $true
      }
    }

    #If the Azure configuration is not there, then skip the Azure tests
    $azSubCount = (Get-Content /home/student/.azure/azureProfile.json | ConvertFrom-Json).Subscriptions.Count
    if( $azSubCount -lt 1) {
      Write-Host "Skipping Azure tests because config files do not exist"
      $skipAzure = $true
    } 
  }

  Context 'Lab 1.2' {
    It 'Part 1 - Host count with ARP' {
      $hostCount = [int](sudo nmap -sn -n 10.50.7.20-110 | grep -c '^Host is up' )
      $hostCount | Should -BeGreaterOrEqual 10
    }

    It 'Part 1 - Host count without ARP' {
      $hostCount = [int](sudo nmap -sn -n --disable-arp-ping 10.50.7.20-110 | grep -c '^Host is up' )
      $hostCount | Should -BeGreaterOrEqual 9
    }

    It 'Part 2 - Stealth scan gets filtered port 80' {
      $portCount = [int]( sudo nmap -sS -p 80 10.50.7.26 | grep -c 'filtered' )
      $portCount | Should -Be 1
    }

    It 'Part 2 - Connect scan gets open port 80' {
      $portCount = [int]( sudo nmap -sT -p 80 10.50.7.26 | grep -c 'open' )
      $portCount | Should -Be 1
    }
    
    It 'Part 3 - OpenSSH version is 8.9p1' {
      $portCount = [int]( sudo nmap -sV -sT -p 22 10.50.7.20-25 | grep -c '8.9p1' )
      $portCount | Should -Be 6
    }
  
    It 'Part 3 - Kubectl shows 4 services' {
      $portList = ( microk8s kubectl get services | awk -F: '/NodePort/ {print $2}' | sed -e 's/\/.*//' )
      $portList | Should -Contain 30020
      $portList | Should -Contain 30022
      $portList | Should -Contain 30023
      $portList | Should -Contain 30024
    }

    It 'Part 3 - K8s Apache versions correct' {
      $verList = ( sudo nmap -sT -p30022-30024 -sV 127.0.0.1 | awk '/Apache/ {print $6}' )
      $verList[0] | Should -Be '2.4.7'
      $verList[1] | Should -Be '2.4.7'
      $verList[2] | Should -Be '2.4.25'
    }
  }
}