# Invoke this test on 507Win10 with this command:
<#
$config=New-PesterConfiguration
$config.Output.Verbosity='detailed'
$config.Run.Path='.\Win10.Labs.tests.ps1'
Invoke-Pester -Configuration $config
#>

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

    #If the Azure configuration is not there, then skip the Azure tests
    $azSubCount = (Get-Content C:\Users\student\.azure\azureProfile.json | ConvertFrom-Json).Subscriptions.Count
    if( $azCount -lt 1) {
      $skipAzure = $true
    } 
    else {
      if(Get-AzTenant.Name -notlike '*sans*'){
        $skipAzure = $true
      }
      else{
        Import-Module Az.Compute
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

  Context 'Lab 1.3 - AWS' -Skip:$skipAWS {
    It 'Part 3 - First user is Amartinez' {
      $username = ( ssh -i C:\users\student\.ssh\ubuntukey student@ubuntu "aws iam list-users --query 'Users[*].{username:UserName}' | jq '.[0].username'" )
      $username | Should -BeLike '*AMartinez*' 
    }

    It 'Part 3 - AWS CLI returns instances' {
      $instanceCount = ((aws ec2 describe-instances --profile default | ConvertFrom-Json).Reservations.Count)
      $instanceCount | Should -BeGreaterOrEqual 5 
    }

    It 'Part 3 - PowerShell module returns instances' {
      (Get-EC2Instance).Count | Should -BeGreaterOrEqual 5
    }

    It 'Part 3 - Get-AWSCmdletName returns multiple results' {
      (Get-AWSCmdletName -ApiOperation describeinstances).Count | 
        Should -BeGreaterOrEqual 3
    }

    It 'Part 3 - Get-AWSCmdletName with service returns correct results' {
      (Get-AWSCmdletName -ApiOperation describeinstances -Service "Amazon Elastic Compute Cloud").CmdletName | 
        Should -Contain 'Get-EC2Instance'
    }
  
    It 'Part 3 - Get-AWSCmdletName with CLI command returns correct results' {
      (Get-AWSCmdletName -AwsCliCommand "aws iam list-users").CmdletName | 
        Should -Contain 'Get-IAMUserList'
      (Get-AWSCmdletName -AwsCliCommand "aws ec2 describe-instances").CmdletName | 
        Should -Contain 'Get-EC2Instance'
    }
  }

  Context 'Lab 1.3 - Azure' -Skip:$skipAzure {
    It 'Part 6 - Get-AZVM returns results'{
      (Get-AzVM).Count | Should -BeGreaterOrEqual 3
    }

    It 'Part 6 - jq processes az vm output' {
      $azvm = (az vm list)
      $prop = (($azvm | jq '[ .[] | { vmname: .name, os: .storageProfile.osDisk.osType, vmsize: .hardwareProfile.vmSize, tags: .tags }]' | 
        ConvertFrom-Json) | Get-Member -Type Properties).Name
        $prop | Should -Contain 'os'
        $prop | Should -Contain 'tags'
        $prop | Should -Contain 'vmname'
        $prop | Should -Contain 'vmsize'
      }

    It 'Part 7 - Powershell converts JSON correctly' {
      (($azvm | ConvertFrom-Json) | Where-Object Name -like '*aud507*').Count | 
        Should -BeGreaterOrEqual 3
    }
  }

  Context 'Lab 1.4 - AWS CLI/PoSh' {
    It 'Part 2 - aws ec2 with jq returns tags' {
      $instanceProperties = (aws ec2 describe-instances |
        jq '[.Reservations[].Instances[0] | { "InstanceId": .InstanceId, "Instancetype": .InstanceType, "Tags":.Tags  }]' |
        ConvertFrom-Json | Get-Member -type Properties).Name
        $instanceProperties | Should -Contain 'InstanceId'
        $instanceProperties | Should -Contain 'Instancetype'
        $instanceProperties | Should -Contain 'Tags'
    }
    
    It 'Part 2 - AWS PowerShell module contains >5,000 of Get* commands'{
      (Get-Command -Module AWSPowerShell.NetCore -name Get-* | Measure-Object).Count | 
        Should -BeGreaterThan 5000
    }

    It 'Part 2 - AWS Powershell returns 3 VPCs' {
      (Get-EC2Vpc).Count | Should -Be 3
    }

    It 'Part 2 - 3 EC2 instances are missing tags' {
      (Get-EC2Instance |  Where-Object { ($_.Instances.tags | Where-Object Key -eq 'Business_Unit').Count -lt 1 }).instances.Count | 
        Should -Be 3
    }
  }

  Context 'Lab 1.4 - Azure' {
    BeforeAll{
      #ensure the resource graph extension and module are installed
      az extension add --name resource-graph
      Import-Module Az.ResourceGraph
    }

    It 'Part 4 - Resource graph extension is installed' {
      (az extension list | ConvertFrom-Json).name | Should -Contain 'resource-graph'
    }

    It 'Part 4 - Resource graph query returns multiple objects' {
      (az graph query -q 'Resources' | ConvertFrom-Json).Count | Should -BeGreaterThan 20
    }

    It 'Part 4 - PowerShell graph query returns multiple objects' {
      $q = 'Resources | order by type | project location, name, type, tags, sku, id'
      $inventory = Search-AzGraph -Query $q
      $inventory.Count | Should -BeGreaterThan 20      
    }
  }

  Context 'Lab 2.1' {
    It 'Part 1 - 5 local users returned' {
      (Get-LocalUsers).Count | Should -Be 5
    }

    It 'Part 2 - Student is only enabled user' {
      $enabledUsers = (Get-LocalUser | Where-Object enabled -eq $true)
      $enabledUsers.Count | Should -Be 1
      $enabledUsers.Name | Should -Contain 'student'
    }
  }

  Context 'Lab 2.2' {
    It 'Part 1 - Build number is 19044' {
      (Get-CimInstance Win32_OperatingSystem).BuildNumber | Should -Be 19044
    }

    It 'Part 1 - At least one hotfix returns' {
      (Get-HotFix).Count | Should -BeGreaterOrEqual 1
    }

    It 'Part 2 - LSA settings correct' {
      $res = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa")
      $res.LimitBlankPasswordUse | Should -Be 1
      $res.NoLMHash | Should -Be 1
      $res.restrictanonymous | Should -Be 0    
      (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" |  Select-Object).EnableLUA | 
        Should -Be 1      
    }

  }
}