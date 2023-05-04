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

    #Check if alma is reachable
    if( -not (Test-NetConnection -InformationLevel Quiet -ComputerName alma.5x7.local) ){
      $skipAlma = $true
    }
    else {
      ssh-keyscan.exe alma >> C:\users\student\.ssh\known_hosts
    }

    #Check if the DC is available
    if( -not (Test-NetConnection -InformationLevel Quiet -ComputerName 507dc.5x7.local) ){
      $skipDC = $true
    }

    #Check if the web server is available
    if( -not (Test-NetConnection -ComputerName 10.50.7.23 -Port 80 -InformationLevel Quiet) ){
      $skipWeb = $true
    }
  }

  Context 'Lab 1.3' {
    It 'Part 3 - First user is Amartinez' {
      $username = ( ssh -i C:\users\student\.ssh\ubuntukey student@ubuntu "aws iam list-users --query 'Users[*].{username:UserName}' | jq '.[0].username'" )
      $username | Should -BeLike '*AMartinez*' 
    }

    It 'Part 3 - AWS CLI returns instances' {
      $instanceCount = ((aws ec2 describe-instances --profile default | ConvertFrom-Json).Reservations.Count)
      $instanceCount | Should -BeGreaterOrEqual 5 
    }

    It 'PowerShell module returns instances' {
      (Get-EC2Instance).Count | Should -BeGreaterOrEqual 5
    }

    It 'Get-AWSCmdletName returns multiple results' {
      (Get-AWSCmdletName -ApiOperation describeinstances).Count | 
        Should -BeGreaterOrEqual 3
    }

    It 'Get-AWSCmdletName with service returns correct results' {
      (Get-AWSCmdletName -ApiOperation describeinstances -Service "Amazon Elastic Compute Cloud").CmdletName | 
        Should -Contain 'Get-EC2Instance'
    }
  }
}