Describe '507 Labs'{
  BeforeDiscovery {

    # Get rid of the known hosts file
    # Remove-Item -Path C:\users\student\.ssh\known_hosts -ErrorAction SilentlyContinue -Force

    #If the AWS config files are not there, then skip the AWS tests
    if( -not ( (Test-Path -Type Leaf -Path C:\users\student\.aws\credentials) -or (Test-Path -Type Leaf -Path C:\users\student\.aws\config) ) ) {
      $skipAWS = $true
    }
    else {
      Import-Module AWSPowershell.NetCore
      #Skip the Cloud Services context if there are no good AWS credentials
      $userARN = (Get-STSCallerIdentity).Arn
      if( $userARN -notlike '*student*'){
        $skipAWS = $true
      }
    }

    #Skip the Linux context if alma is unreachable
    if( -not (Test-NetConnection -InformationLevel Quiet -ComputerName alma.5x7.local) ){
      $skipAlma = $true
    }
    else {
      ssh-keyscan.exe alma >> C:\users\student\.ssh\known_hosts
    }

    #Skip the Kubernetes and OSQuery Linux context if Ubuntu is unreachable
    if( -not (Test-NetConnection -InformationLevel Quiet -ComputerName ubuntu.5x7.local) ){
      $skipUbuntu = $true
    }
    else {
      ssh-keyscan.exe ubuntu >> C:\users\student\.ssh\known_hosts
    }

    #Skip domain tests if the DC is not available
    if( -not (Test-NetConnection -InformationLevel Quiet -ComputerName 507dc.5x7.local) ){
      $skipDC = $true
    }

    #Skip web app tests if the web server is not available
    if( -not (Test-NetConnection -ComputerName 10.50.7.23 -Port 80 -InformationLevel Quiet) ){
      $skipWeb = $true
    }
  }

  Context 'Lab 1.2' {
    It 'Part 1 - Host count with ARP' {
      $hostCount = (ssh -i C:\users\student\.ssh\ubuntukey student@ubuntu "sudo nmap -sn -n 10.50.7.20-110 | grep -c '^Host is up'")
      $hostCount | Should -be 12
    }

    It 'Part 1 - Host count without ARP' {
      $hostCount = (ssh -i C:\users\student\.ssh\ubuntukey student@ubuntu "sudo nmap -sn -n --disable-arp-ping 10.50.7.20-110 | grep -c '^Host is up'")
      $hostCount | Should -be 11
    }

    It 'Part 2 - Stealth scan gets filtered port 80' {
      $portCount = ( ssh -i C:\users\student\.ssh\ubuntukey student@ubuntu "sudo nmap -sS -p 80 10.50.7.26 | grep -c 'filtered'")
      $portCount | Should -Be 1
    }

    It 'Part 2 - Connect scan gets open port 80' {
      $portCount = ( ssh -i C:\users\student\.ssh\ubuntukey student@ubuntu "sudo nmap -sT -p 80 10.50.7.26 | grep -c 'open'")
      $portCount | Should -Be 1
    }
    
    It 'Part 3 - OpenSSH version is 8.9p1' {
      $portCount = ( ssh -i C:\users\student\.ssh\ubuntukey student@ubuntu "sudo nmap -sV -sT -p 22 10.50.7.20-25 | grep -c '8.9p1'" )
      $portCount | Should -Be 6
    }
  
    It 'Part 3 - Kubectl shows 4 services' {
      $portList = ( ssh -i C:\users\student\.ssh\ubuntukey student@ubuntu "microk8s kubectl get services | awk -F: '/NodePort/ {print `$2}' | sed -e 's/\/.*//'" )
      $portList | Should -Contain 30020
      $portList | Should -Contain 30022
      $portList | Should -Contain 30023
      $portList | Should -Contain 30024
    }

    It 'Part 3 - K8s Apache versions correct' {
      $verList = ( ssh -i C:\users\student\.ssh\ubuntukey student@ubuntu "sudo nmap -sT -p30022-30024 -sV 127.0.0.1 | awk '/Apache/ {print `$6}'" )
      $verList[0] | Should -Be '2.4.7'
      $verList[1] | Should -Be '2.4.7'
      $verList[2] | Should -Be '2.4.25'
    }
  }

  Context 'Lab 1.3' {
    It 'Part 3 - First user is Amartinez' {
      $username = ( ssh -i C:\users\student\.ssh\ubuntukey student@ubuntu "aws iam list-users --query 'Users[*].{username:UserName}' | jq '.[0].username'" )
      $username | Should -BeLike '*AMartinez*' 
          
    }
  }
}