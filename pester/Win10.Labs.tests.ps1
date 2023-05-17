# Invoke this test on 507Win10 with these commands:
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
    
    $PSDefaultParameterValues['Test-NetConnection:InformationLevel'] = 'Quiet'

    #If the AWS config files are not there, then skip the AWS tests
    if( -not ( (Test-Path -Type Leaf -Path C:\users\student\.aws\credentials) -or (Test-Path -Type Leaf -Path C:\users\student\.aws\config) ) ) {
      Write-Host "Skipping AWS tests because config files do not exist"
      $skipAWS = $true
    }
    else {
      Write-Host 'Importing AWSPowershell.NetCore'
      Import-Module AWSPowershell.NetCore
      Write-Host 'Import complete'

      #Skip the Cloud Services context if there are no good AWS credentials
      $userARN = (Get-STSCallerIdentity).Arn
      if( $userARN -notlike '*student*'){
        Write-Host "Skipping AWS tests because Get-STSCallerIdentity did not return valid ARN"
        $skipAWS = $true
      }
    }

    #If the Azure configuration is not there, then skip the Azure tests
    $azSubCount = (Get-Content C:\Users\student\.azure\azureProfile.json | ConvertFrom-Json).Subscriptions.Count
    if( $azSubCount -lt 1) {
      Write-Host "Skipping Azure tests because config files do not exist"
      $skipAzure = $true
    } 
    else {
      Write-Host 'Importing AZ Accounts module'
      Import-Module Az.Accounts
      Write-Host 'Import complete'

      Write-Host 'Importing AZ Compute module'
      Import-Module Az.Compute
      Write-Host 'Import complete'

      if((Get-AzTenant).Name -notlike '*sans*'){
        Write-Host "Skipping Azure tests because tenant is not correct"
        $skipAzure = $true
      }
    }

    #Check if esxi server is reachable
    if( -not (Test-NetConnection -InformationLevel Quiet -ComputerName esxi.5x7.local) ){
      Write-Host "Skipping ESXi tests because host is unreachable"
      $skipEsxi = $true
    }
    else {
      Write-Host 'Importing PowerCLI - may be slow!'
      Import-Module VMware.PowerCLI
      Write-Host 'Import complete'
    }
    

    #Check if alma is reachable
    if( -not (Test-NetConnection -InformationLevel Quiet -ComputerName alma.5x7.local) ){
      Write-Host "Skipping alma tests because host is unreachable"
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
      $username = (aws iam list-users --query 'Users[*].{username:UserName}' | jq '.[0].username' )
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
      $azvm = (az vm list)
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
      (Get-LocalUser).Count | Should -Be 5
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

    It 'Part 3 - Firefox not in the Win32_Product list'{
      $res = (Get-CimInstance Win32_Product | Select-Object Name, Version )
      ($res | Where-Object Name -like '*mozilla*').Count | Should -Be 0
    }

    It 'Part 3 - InstalledSoftware script output includes Firefox'{
      $res = C:\users\student\AUD507-Labs\scripts\InstalledSoftware.ps1
      ($res | Where-Object Displayname -like '*mozilla*').Count | Should -BeGreaterOrEqual 1

    }

    It 'Part 5 - OSQuery returns Firefox' {
      $res = osqueryi.exe "select name, version, install_date from programs;" --json | ConvertFrom-Json | Where-Object Name -like '*mozilla*'
      $res.Count | Should -BeGreaterOrEqual 1
    }

    It 'Part 5 - OSQuery returns 2 admin users' {
      $query = "select username, groupname, type 
      from users join user_groups on user_groups.UID = users.uid 
      join groups on groups.gid = user_groups.gid 
      where groups.groupname ='Administrators';"

      $res = (osqueryi.exe "$query" --json | ConvertFrom-Json)
      $res.Username | Should -Contain 'Administrator'
      $res.Username | Should -Contain 'student'
    }

    It 'Part 5 - OSQuery returns 1 for LimitBlankPasswordUse' {
      $query = "select data, path from registry 
      where path= 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\LimitBlankPasswordUse';
      "

      $res = (osqueryi.exe "$query" --json | ConvertFrom-Json)
      $res.Count | Should -Be 1
      $res.Data | Should -Be 1
    }
  }

  Context 'Lab 2.3' {
    BeforeAll {
      $User = "student"
      $PWord = ConvertTo-SecureString -String "Password1" -AsPlainText -Force
      $cred = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $User, $PWord
    }

    It 'Part 2 - Get-LocalGroupMember returns correct admins' {
      $res = (Get-LocalGroupMember -Group "administrators")
      $res.Name | Should -Contain '507WIN10\Administrator'
      $res.Name | Should -Contain '507WIN10\Student'
    }

    It 'Part 2 - UserRights.psm1 returns admin for debug privilege' {
      Import-Module C:\users\student\AUD507-Labs\scripts\UserRights.psm1
      $res = (Get-AccountsWithUserRight -Right SeDebugPrivilege).account
      $res | Should -Contain 'BUILTIN\Administrators'
    }

    It 'Part 2 - UserRights.psm1 returns 0 privileges for student' {
      (Get-UserRightsGrantedToAccount -Account student).Count | Should -Be 0 
    }

    It 'Part 2 - UserRights.psm1 returns 27 privileges for admins' {
      (Get-UserRightsGrantedToAccount -Account administrators).Count | Should -Be 27
    }

    It 'Part 3 - Get-ACL returns numeric ACL' {
      (Get-Acl c:\windows).AccessToString | Should -BeLike '*268435456*'
    }

    It 'Part 3 - Get-FileShare returns 2 shares' {
      $res = (Get-FileShare)
      $res.Count | Should -Be 2
      $res.Name | Should -Contain 'ADMIN$'
      $res.Name | Should -Contain 'C$'
    }
    
    It 'Part 3 - Get-SMBShare returns 2 shares' {
      $res = (get-SMBShare)
      $res.Count | Should -Be 3
      $res.Name | Should -Contain 'ADMIN$'
      $res.Name | Should -Contain 'C$'
      $res.Name | Should -Contain 'IPC$'
    }
  }

  Context 'Lab 2.3: AWS VPN to DC' -Skip:$skipDC { 
    BeforeAll {
      $User = "student"
      $PWord = ConvertTo-SecureString -String "Password1" -AsPlainText -Force
      $cred = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $User, $PWord
    }
    
    It 'Part 5 - 1007 AD users returned' {
      (Get-ADUser -Filter * -Server 507dc -Credential $cred).Count | Should -Be 1007
    }

    It 'Part 5 - 2 users without password required' {
      (Get-ADUser -Filter {PasswordNotRequired -eq $true} `
        -Server 507dc -Credential $cred).Count | Should -Be 2
    }

    It 'Part 5 - 9 users without password expiration' {
      (Get-ADUser -Filter {PasswordNotRequired -eq $true} `
        -Server 507dc -Credential $cred).Count | Should -Be 2
    }

    It 'Part 5 - 5 domain admins without recursion' {
      (Get-ADGroupMember -Identity "Domain Admins" `
        -Server 507dc -Credential $cred).Count | Should -Be 5
    }

    It 'Part 5 - 71 domain admins with recursion' {
      (Get-ADGroupMember -Identity "Domain Admins" `
      -Server 507dc -Credential $cred -Recursive).Count | Should -Be 71
    }

    It 'Part 5 - Student is a domain admin' {
      (Get-ADPrincipalGroupMembership -Identity "student" `
        -Server 507dc -Credential $cred).Name | Should -Contain 'Domain Admins'
    }

    It 'Part 5 - DSGet shows student in Schema Admins' {
      $userDN = (Get-ADUser -Identity student `
        -Server 507dc -Credential $cred).DistinguishedName
      $res = dsget user "$userDN" -memberof -expand -s 507dc -u student -p Password1
      $res | Should -Contain '"CN=Schema Admins,CN=Users,DC=AUD507,DC=local"'
      $res | Should -Contain '"CN=Domain Admins,CN=Users,DC=AUD507,DC=local"'
    }

    #Inactive/Active user counts don't really make sense in the lab, so we don't test them
    It 'Part 5 - ADAuditGeneric script returns expected results' {
      Write-Host "Running AD audit script"
      $res = (C:\Users\student\AUD507-Labs\scripts\ADAuditGeneric.ps1 -Server 507dc -Credential $cred)
      $res.NetBiosName | Should -Be 'AUD507'
      $res.DNSRoot | Should -Be 'AUD507.local'
      $res.Forest | Should -Be 'AUD507.local'
      $res.ADFunctionalLevel | Should -Be 'Windows2016Domain'
      $res.EnabledUsers | Should -Be 996 
      $res.DisabledUsers | Should -Be 11
      $res.TotalUsers | Should -Be 1007
      $res.StalePasswordUsers | Should -Be 0
      $res.DomainAdmins | Should -Be 71
      $res.SchemaAdmins | Should -Be 71
      $res.EnterpriseAdmins | Should -Be 1
      $res.PasswordNeverExpires | Should -Be 8
      $res.PasswordNeverSet | Should -Be 0
      $res.PasswordNotRequired | Should -Be 1
    }
  }

  Context 'Lab4.1-VMWare' -Skip:$skipEsxi {
    BeforeAll {
      Set-PowerCLIConfiguration -Scope User -ParticipateInCEIP $false -Confirm:$false
      Set-PowerCLIConfiguration -Scope User -DefaultVIServerMode Single -Confirm:$false
      Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -Confirm:$false

      $User = "student"
      $PWord = ConvertTo-SecureString -String "Password1!" -AsPlainText -Force
      $vmwareCred = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $User, $PWord

      Connect-VIServer -Server esxi1 -Credential $vmwareCred
    }

    #Set back to defaults
    AfterAll {
      Set-PowerCLIConfiguration -Scope User -DefaultVIServerMode Multiple -Confirm:$false
      Set-PowerCLIConfiguration -InvalidCertificateAction Fail -Confirm:$false
    }

    It 'Part 2 - Get-VM returns 2 VMs' {
      (Get-VM).Count | Should -Be 2
    }

    It 'Part 2 - DNS server settings are correct' {
      $dnsservers = ((Get-VMHost).ExtensionData.Config.Network.DNSConfig |  
        Select-Object -ExpandProperty address)
      $dnsservers | Should -Contain '8.8.8.8'
      $dnsservers | Should -Not -Contain '8.8.4.4'
    }

    It 'Part 2 - NTP Server is correct' {
      $ntpServer = (Get-VMHost -Server esxi1 | Get-VMHostNtpServer)
      $ntpServer | Should -Be 'pool.ntp.org'
    }

    It 'Part 2 - NTP service state is correct' {
      $ntpState = (Get-VMHost | Get-VMHostService | Where-Object {$_.key -eq "ntpd"} |
        Select-Object VMHost, Label, Key, Policy, Running, Required)
        $ntpState.Policy | Should -Be 'off'
        $ntpState.Running | Should -Be $false
        $ntpState.Required | Should -Be $false
    }

    It 'Part 2 - Datastore version is > 6' {
      $ds = (Get-VMHost -Server esxi1 | Get-Datastore)
      $ds.FileSystemVersion | Should -BeGreaterOrEqual 6
    }
  }

  Context 'Lab 4.2' {
    It 'Part 1 - IAM account summary results correct' {
      $res = (Get-IAMAccountSummary)
      $res.AccountAccessKeysPresent | Should -Be 0
      $res.AccountMFAEnabled | Should -Be 1
    }

    It 'Part 1 - Student user has only 1 key' {
      $myusername = (Get-STSCallerIdentity).Arn -replace ".*\/", ""
      (Get-IAMAccessKey -UserName $myusername).Count | Should -Be 1
    }

    It 'Part 1 - GLee has 2 keys' {
      $userName  = (Get-IAMUserList | Where-Object UserName -like 'GLee*').UserName
      $keyCount = (Get-IAMAccessKey -UserName $userName).Count
      $keyCount | Should -Be 2
    }

    It 'Part 1 - JAllen has AWSSupportAccess policy attached' {
      $userName = (Get-IAMUserList | Where-Object username -like 'JAllen*').UserName
      $res = (Get-IAMAttachedUserPolicies -UserName $userName)
      $res.Count | Should -Be 1
      $res[0].PolicyName | Should -Be 'AWSSupportAccess'
    }

    It 'Part 1 - Walexander has inline policy' {
      $userName = (Get-IAMUserList | Where-Object username -like 'Walexander*').UserName
      $res = (Get-IAMUserPolicies -UserName $userName)
      $res.Count | Should -Be 1
    }
  }

  Context 'Lab 4.4' {
    It 'Part 4 - 4 buckets have server side encryption enabled' {
      $res = ((Get-S3Bucket | Get-S3BucketEncryption).ServerSideEncryptionRules | 
        Where-Object ServerSideEncryptionByDefault -ne $null)
      $res.Count | Should -Be 4
    }

    It 'Part 4 - 4 buckets have versioning turned off' {
      $res = (Get-S3Bucket | Get-S3BucketVersioning | Where-Object Status -eq 'Off')
      $res.Count | Should -Be 4
    }

    
    It 'Part 4 - 4 buckets have MFA Delete turned off' {
      $res = (Get-S3Bucket | Get-S3BucketVersioning | Where-Object EnableMfaDelete -eq $false)
      $res.Count | Should -Be 4
    }
  }

  Context 'Lab 5.2' {
    It 'Part 1 - Juiceshop shows self-signed cert' {
      $sslyzeRes = (C:\tools\sslyze\sslyze.exe --certinfo juiceshop.5x7.local:443)
      ($sslyzeRes -like '*Issuer*juiceshop.5x7.local').Count | Should -Be 1
    }

    It 'Part 1 - Cert expiration is 2032-11-19' {
      $sslyzeRes = (C:\tools\sslyze\sslyze.exe --certinfo juiceshop.5x7.local:443)
      ($sslyzeRes -like '*Not After*2032-11-19').Count | Should -Be 1
    }

    It 'Part 1 - Windows CA store test fails' {
      $sslyzeRes = (C:\tools\sslyze\sslyze.exe --certinfo juiceshop.5x7.local:443)
      ($sslyzeRes -like '*Windows CA Store*FAILED*').Count | Should -Be 1
    }

    It 'Part 1 - SSLv3 disabled' {
      $sslyzeRes = (C:\tools\sslyze\sslyze.exe --sslv3 juiceshop.5x7.local:443)
      ($sslyzeRes -like '*the server rejected all cipher suites*').Count | Should -Be 1
    }

    It 'Part 1 - TLS1.0 disabled' {
      $sslyzeRes = (C:\tools\sslyze\sslyze.exe --tlsv1 juiceshop.5x7.local:443)
      ($sslyzeRes -like '*the server rejected all cipher suites*').Count | Should -Be 1
    }

    It 'Part 1 - TLS1.1 disabled' {
      $sslyzeRes = (C:\tools\sslyze\sslyze.exe --tlsv1_1 juiceshop.5x7.local:443)
      ($sslyzeRes -like '*the server rejected all cipher suites*').Count | Should -Be 1
    }

    It 'Part 1 - TLS1.2 enabled' {
      $sslyzeRes = (C:\tools\sslyze\sslyze.exe --tlsv1_2 juiceshop.5x7.local:443)
      ($sslyzeRes -like '*The server accepted the following 27*').Count | Should -Be 1
    }

    It 'Part 1 - TLS1.3 enabled' {
      $sslyzeRes = (C:\tools\sslyze\sslyze.exe --tlsv1_3 juiceshop.5x7.local:443)
      ($sslyzeRes -like '*The server accepted the following 3*').Count | Should -Be 1
    }
  }
}