#Requires -RunAsAdministrator

Describe 'Tests for Win10 VM' {

    BeforeAll {
        $password = ConvertTo-SecureString "Password1" -AsPlainText -Force
        $studentCred = New-Object System.Management.Automation.PSCredential ("auditor", $password)
        $password = ConvertTo-SecureString "Password1!" -AsPlainText -Force
        $esxiCred = New-Object System.Management.Automation.PSCredential ("auditor", $password)
        $basePath = (Get-Item ENV:UserProfile).Value
    }
    Context 'General Setup' {
        #Check that DNS resolution is happening quickly
        BeforeAll {
            $startTime = Get-Date
            $ip = Resolve-DnsName 'dns.google'
            $endTime = Get-Date
        }
        It 'DNS resolves IP for dns.google' {
            $ip.IPAddress | Should -Contain '8.8.8.8'
        }
        It 'DNS resolves in < 5 seconds' {
            $elapsed = New-TimeSpan -Start $startTime -End $endTime
            $elapsed.totalSeconds | Should -BeLessThan 5
        }
        #Use test-netConnection to verify that TCP port 2003 
        #is reachable on ubuntu host
        It 'Graphite service is reachable on Ubuntu' {
            Test-NetConnection -ComputerName ubuntu -Port 2003 -InformationLevel Quiet | 
                Should -beTrue
        }
    }
    #Check versions for installed software
    Context 'Software Versions'{
        BeforeAll {
            #Use the list from OSQuery
            #If OSQuery is not installed, then several tests will fail
            $softwareVersions = osqueryi 'select name,version from programs;' --json | ConvertFrom-Json
        }
        #Check for VMWare Tools. Version does not matter
        It 'VMware tools is installed' {
            $softwareVersions.Name | Should -Contain 'VMware Tools'
        }
        #Expected version of SOAP UI is installed
        #New versions may require new screenshots
        It 'SoapUI as the correct version'{
            ($softwareVersions | Where-Object name -like 'SoapUI*').Version | Should -BeLike '5.*'
        }
        #use 'jq.exe -V' to check version of jq.exe
        #current version is 'jq-1.6'
        It 'jq.exe is correct version' {
            jq.exe -V | should -be 'jq-1.6'
        }
        #Check that we got results from OSQuery
        It 'OSqueryi returns results' {
            $softwareVersions.Count | Should -beGreaterThan 0
        }
        It 'OSqueryd service is running' {
            (Get-Service osqueryd).Status | Should -Be 'Running'
        }
        # It 'WSL netcat is installed' {
        #     $res = wsl nc -h 2>&1
        #     $res[0] | Should -BeLike '*netcat*'
        # }
    }
    Context 'Lab0'{
        BeforeAll {
            $gitStatus = (git status)
        }

        #Check that the web UI for Grafana is reachable
        #The Ubuntu VM needs to be running for this test to pass
        #Ensure that a 200 status code is returned by the server
        It 'Grafana is reachable' {
            $uri = 'http://dashboard.sec557.local:3000/'
            (Invoke-WebRequest -Uri $uri).StatusCode | 
                Should -Be 200
        }
        It 'Fleet is reachable' {
            $uri = 'https://fleet.sec557.local:8443'
            (Invoke-WebRequest -SkipCertificateCheck -Uri $uri).StatusCode | 
                Should -Be 200
        }
        It 'Git is on correct branch' {
            $gitStatus[0] | Should -Be 'On branch H01'
        }
    }
    Context 'Lab1.1'{
        It 'Get-LocalUser returns 6 users' {
            (Get-LocalUser).count | Should -be 6
        }
        It 'Get-LocalUser returns 2 enabled users' {
             (Get-LocalUser |  Where-Object Enabled -eq $true).count | Should -be 2
        }


    }
    Context 'Lab1.2'{
        #Use Test-Path to ensure that the XML file for the books
        #database exists
        It 'Books.xml exists' {
            Test-Path -path $basePath\SEC557Labs\Lab1.2\books.xml -Pathtype Leaf | Should -beTrue
        }
        #Check that the file contains the correct data
        It 'Books catalog contains 12 books' {
            $xBooks = New-Object System.Xml.XmlDocument
            $file=Resolve-Path "$basePath\SEC557Labs\Lab1.2\books.xml"
            $xBooks.Load($file)
            $xBooks.catalog.book.count | Should -be 12
        }
        #Use Test-Path to ensure that the XML file for the NMAP
        #scan exists
        It 'nmapScan.xml exits'{
            Test-Path -path $basePath\SEC557Labs\Lab1.2\nmapScan.xml -Pathtype Leaf | Should -beTrue
        }
        #Check that the NMAP XML file has correct results in it
        #TODO: Finish this test
        It 'NMAP scan has 59 open ports'{
            $xScan = New-Object System.Xml.XmlDocument
            $file = Resolve-Path "$basePath\SEC557Labs\Lab1.2\nmapScan.xml"
            $xScan.load($file)
            $cnt = ($xScan.SelectNodes("/nmaprun/host/ports/port") |  
                select portid -ExpandProperty state | Where-Object state -eq open).count

            $cnt | Should -be 59
        }
        #Check that the 81 CSV files are in the VulnScanResults subdirectory
        #Use Get-ChildItem on that full directory path and count the results
        It 'Vulnerabilty scan directory has 81 CSV files'{
            (get-childitem -path $basePath\SEC557Labs\Lab1.2\VulnScanResults\*.csv).count | should -be 81
        }
        #Ingest the CSVs and make sure that the correct number of
        #Nessus results are there
        It 'Vulnerabilty scans have 29834 results'{
            $scanResults = Import-Csv -path (Get-childitem $basePath\SEC557Labs\Lab1.2\VulnScanResults\*.csv ) 
            $scanResults.count | should -be 29834
        }
    }

    Context 'Lab1.3'{
        It 'tabledemo.json exist in directory'{
            Test-Path -path $basePath\SEC557Labs\Lab1.3\tabledemo.json -Pathtype Leaf | Should -beTrue
        }
    }

    Context 'Lab1.4'{
        It 'pyramid.json exist in directory'{
            Test-Path -path $basePath\SEC557Labs\Lab1.4\pyramid.json -Pathtype Leaf | Should -beTrue
        }
    }

    Context 'Lab2.1'{
        #Validate that the web service is available and returning values
        #Windows PowerShell is easier to test with
        It 'Windows PowerShell can call web service' {
            $result = powershell.exe -file .\wsp.ps1
            $result | Should -Be 'one dollar'
        }
    }

    Context 'Lab 2.2'{
        #Get 100 Github closed issues into a variable for testing
        BeforeAll {
            $uri = "https://api.github.com/repos/PowerShell/PowerShell/issues?per_page=10`&state=closed"
            $issueResponse = Invoke-WebRequest -Uri $uri
            $issueContent = $issueResponse.Content
            $issues = Invoke-RestMethod -Method Get -Uri $uri
        }
        It 'Github issues API returns 10 results' {
            $issues.Count | Should -Be 10
        }
        #Run a command with jq to make sure it processes okay
        It 'jq parses issue title'{
            $issueContent | jq '.[0].created_at' |
                Should -Not -BeNullOrEmpty
        }
        #Make sure that the student MTTR calculation returns a number > 0
        It 'MTTR returns calculation returns a positive result' {
            ($issues | 
                Select-Object @{n='TimeToResolve'; `
                    e={(New-TimeSpan -Start (Get-Date -date $_.created_at) `
                    -End ($_.closed_at)).TotalDays} } |  
                Measure-Object -Property TimeToResolve -Average).Average | 
                Should -BeGreaterThan 0
        }
    }
    #This lab rehashes some of the commands from the previous lab,
    #but it needs the secrets modules, so test that they are installed
    #and working
    Context 'Lab2.3'{
        #Load the modules so we can test them
        BeforeAll {
            Import-Module Microsoft.PowerShell.SecretManagement
            Import-Module Microsoft.PowerShell.SecretStore
        }
        #Use Get-Command to make sure that Get-Secret is included 
        #in the SecretManagement module
        It 'SecretManagement module contains Get-Secret command'{
            (get-command -module Microsoft.PowerShell.SecretManagement).Name |should -contain 'Get-secret'
        }
        #Use Get-Command to make sure that  Get-SecretStoreConfiguration is included 
        #in the SecretStore module  
        It 'SecretStore module contains Get-SecretStoreConfiguration command'{
            (get-command -module Microsoft.PowerShell.SecretStore).Name |should -contain 'Get-SecretStoreConfiguration'
        }    
    }
    #Students manually configure a scheduled task in this lab
    #We'll just check to see that the correct files all exist
    #using the Test-path command and full file paths
    Context 'Lab2.4'{
        It 'AutomationFunctions.ps1 exists in lab directory'{
            Test-Path -path $basePath\SEC557Labs\Lab2.4\AutomationFunctions.ps1 -Pathtype Leaf | Should -beTrue
        }
        It 'GithubIssues.ps1 exists in lab directory'{
            Test-Path -path $basePath\SEC557Labs\Lab2.4\GithubIssues.ps1 -Pathtype Leaf | Should -beTrue
        }
        It 'Run-GithubIssues.ps1 exists in lab directory'{
            Test-Path -path $basePath\SEC557Labs\Lab2.4\Run-GithubIssues.ps1 -Pathtype Leaf | Should -beTrue
        }
        It 'GithubIssues.xml exists in lab directory'{
            Test-Path -path $basePath\SEC557Labs\Lab2.4\GithubIssues.xml -Pathtype Leaf | Should -beTrue
        }
        It 'issues.json exists in lab directory'{
            Test-Path -path $basePath\SEC557Labs\Lab2.4\issues.json -Pathtype Leaf | Should -beTrue
        }
    }
    Context 'Lab3.1'{
        #Run the script to create the student data files
        #Using Push- and Pop-Location so that the file will be created in the right place
        BeforeAll{
            Push-Location $basePath\SEC557Labs\Lab3.1\
            .\GetPatchData.ps1
            $patchAgeData = Import-Csv .\patchAge.csv
            $patchdata = Import-Csv .\patches.csv
        }
        AfterAll{
            Remove-Item patches.csv
            Remove-Item patchAge.csv
            Pop-Location
        }
        It 'GetpatchData.ps1 script exists'{
            Test-Path -path $basePath\SEC557Labs\Lab3.1\GetPatchData.ps1 -Pathtype Leaf | Should -beTrue
        }
        It 'patches.json exists'{
            Test-Path -path $basePath\SEC557Labs\Lab3.1\patches.json -Pathtype Leaf | Should -beTrue
        }
        It 'patchAge.csv contains 36600 records'{
            $patchAgeData.count | should -be 36600
        }
        It 'patches.csv has 12840 records' {
            $patchData.count | should -be 12840
        }
        It 'patchAge.csv contains 100 servers' {
            $servers = $patchdata | Select-Object Source -Unique
            $servers.Count | Should -Be 100
        }
    }
    Context 'Lab3.2'{
        #Students are asked to use secedit to export local security policy
        BeforeAll {
            Push-Location $basePath\SEC557Labs\Lab3.2\
            SecEdit.exe /export /cfg localSecPolicyPester.txt
            $localPolicy = Get-Content .\localSecPolicyPester.txt
        }
        AfterAll {
            Remove-Item $basePath\SEC557Labs\Lab3.2\localSecPolicyPester.txt
            Pop-Location
        }
        #Use Get-Module to check the version of the Pester module
        It 'Pester is at least version 5'{
            (Get-Module -ListAvailable Pester).version.major |should -contain 5
        }
        #Verify that user testing results will match the lab
        It 'Local administrator account is disabled' {
            (Get-LocalUser -Name Administrator).Enabled | should -beFalse
        }
        It 'Local guest account is disabled' {
            (Get-LocalUser -Name guest).Enabled | Should -beFalse
        }
        It 'Local administrator group has 2 members' {
            (Get-LocalGroupMember -Name Administrators | Measure-Object).Count | Should -BeGreaterOrEqual 2
        }
        #Verify OSQueryd results will match lab
        It 'OSQueryd is installed' {
            (Get-Service).name | should -contain 'osqueryd'
        }
        It 'OSQueryd is running' {
            (Get-Service -name 'osqueryd').status | should -be 'running' 
        }
        It 'OSQueryd is has automatic startup' {
            (Get-Service -name 'osqueryd').startType | should -be 'automatic'
        }
        #Validate that the registry tests done by the student 
        #will return correct results
        It 'LSA LimitBlankPasswordUse is 1' {
            $lsa = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa")
            $lsa.LimitBlankPasswordUse | should -be 1
        }
        It 'LSA NoLMHash is 1' {
            $lsa = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa")
            $lsa.NoLMHash | should -be 1
        }
        It 'LSA RestrictAnonymous is 0' {
            $lsa = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa")
            $lsa.RestrictAnonymous | should -be 0
        }
        It 'Minimum Password Age is 0' {
            #Find the MinimumPasswordAge setting in the text file
            $MinPwdAge = ($localPolicy | Select-String "MinimumPasswordAge" -NoEmphasis) `
                -Replace 'MinimumPasswordAge = ', ''
            $MinPwdAge | Should -Be '0'
        }
        It 'BackupPrivilege Contains Administrators and backup Operators Groups' {
            $backupUsers = ($localPolicy | Select-String "SeBackupPrivilege" -NoEmphasis) `
                -Replace 'SeBackupPrivilege = ', '' -Split "," -replace '\*', ''
            $groupNames=($backupUsers | foreach { Get-LocalGroup | Where-Object Sid -eq $_ }).Name
            $groupNames | Should -Contain 'Administrators'
            $groupNames | Should -Contain 'Backup Operators'
        }
        It 'InstalledSoftware.ps1 shows Firefox' {
            $programNames = (& "$basePath\SEC557Labs\Lab3.2\InstalledSoftware.ps1")
            ($programNames | Where-Object DisplayName -like '*firefox*').Count | 
                Should -Be 1
        }

        It 'Windows.Tests.ps1 has 7 passed tests and 2 failed' {
            $pesterResult = Invoke-Pester -Path $basePath\SEC557Labs\Lab3.2\\Windows.Tests.ps1 -PassThru
            $pesterResult.FailedCount | Should -Be 2
            $pesterResult.PassedCount | Should -Be 7
        }
        It 'PesterIntro.tests.ps1 has 10 passed tests and 2 failed' {
            $pesterResult = Invoke-Pester -Path $basePath\SEC557Labs\Lab3.2\\pesterintro.Tests.ps1 -PassThru
            $pesterResult.passedCount | Should -Be 10
            $pesterResult.failedCount | Should -Be 2
        }

        #verify that C:\tools\extent.exe exists on the VM
        It 'ExtentReport is installed' {
            Test-Path -path C:\tools\extent.exe -Pathtype Leaf | Should -beTrue
        }
    }
    Context 'Lab3.3'{
        BeforeAll{
            Import-Module ActiveDirectory
            $ServerPort = "10.50.7.10:389"
            New-PSDrive -name "ADAudit" -PSProvider ActiveDirectory -Root "" `
                -Server $ServerPort -Credential $studentCred
            Push-Location ADAudit:
            $InactiveDays = 120
        }
        AfterAll {
            Pop-Location
            Remove-PSDrive -name "ADAudit"
        }
        It 'AD NetBIOS name is AUD507'{
            $NetBIOSName = (Get-ADDomain | Select-Object NetBIOSName).NetBIOSName
            $NetBIOSName | Should -Be 'AUD507'
        }
        It 'AD DNSRoot name is AUD507.local'{
            $NetBIOSRoot = (Get-ADDomain | Select-Object DNSRoot).DNSRoot
            $NetBIOSRoot | Should -Be 'AUD507.local'
        }
        It 'AD Forest name is AUD507.local'{
            $forest = (Get-ADDomain | Select-Object Forest).Forest
            $forest | Should -Be 'AUD507.local'
        }
        It 'AD functional level is  Windows2016Domain'{
            $ADFunctionalLevel = (Get-ADDomain | Select-Object DomainMode).DomainMode.ToString()
            $ADFunctionalLevel | Should -Be 'Windows2016Domain'
        }
        It 'AD active users count should be 977' {
            $EnabledUsers = (Get-ADUser -Filter 'enabled -eq $true' | Measure-Object).Count
            $EnabledUsers | Should -Be 977
        }
        It 'AD disabled users count should be 12' {
            $DisabledUsers = (Get-ADUser -Filter 'enabled -eq $false').Count
            $DisabledUsers | Should -Be 12
        }
        It 'AD total users count should be 989' {
            $TotalUsers = (Get-ADUser -filter * | Measure-Object).Count
            $TotalUsers | Should -be 989
        }
        It 'Stale password users count should be > 970' {
            $StalePasswordUsers = `
                (Get-ADUser -Filter 'enabled -eq $true' `
                -Properties SAMAccountName,PasswordLastSet,WhenCreated | 
                Where-Object { ($_.WhenCreated -lt (Get-Date).AddDays( -$InactiveDays )) -and `
                ($_.passwordLastSet -lt (Get-Date).AddDays( -$InactiveDays )) } ).Count
            $StalePasswordUsers | Should -beGreaterThan 970
        }
        It 'Inactive users count should be > 970' {
            $InactiveUsers = (Get-ADUser -Filter 'enabled -eq $true' `
                -Properties SAMAccountName,LastLogonDate,WhenCreated,PasswordLastSet |
                Where-Object { `
                ($_.LastLogonDate -lt (Get-Date).AddDays( -$InactiveDays )) } ).Count
            $InactiveUsers | should -beGreaterThan 970
        }
        #We'll pad a bit on this one, since the student user may show up as active
        #Most of the time, the result should be zero
        It 'Active users count should be less than 2' {
            $ActiveUsers = (Get-ADUser -Filter 'enabled -eq $true' `
                -Properties SAMAccountName,LastLogonDate,WhenCreated,PasswordLastSet |
                Where-Object { ($_.LastLogonDate -gt (Get-Date).AddDays( -$InactiveDays )) `
                -or ($_.passwordLastSet -gt (Get-Date).AddDays( -$InactiveDays )) } | 
                Measure-Object).Count
            $ActiveUsers | should -beLessThan 2
        }
        It 'Password never expires users count should be 8' {
            $PasswordNeverExpires = (Get-ADUser -filter `
                {PasswordNeverExpires -eq $true -and Enabled -eq $true} ).Count
            $PasswordNeverExpires | Should -be 8
        }
        It 'Password not required users count should be less than 2' {
            $PasswordNotRequired = ` (Get-ADUser -Filter 'enabled -eq $true -and PasswordNotRequired -eq $true' |  
                Measure-Object).Count
            $PasswordNotRequired | Should -beLessThan 2
        }
        It 'Domain admin count is 70' {
            $DomainAdmins = (Get-ADGroupMember -Recursive `
                -Identity "Domain Admins" ).Count
            $DomainAdmins | should -be 70
        }
        It 'Schema admin count is 70' {
            $SchemaAdmins = (Get-ADGroupMember -Recursive `
                -Identity "Schema Admins" ).Count
            $SchemaAdmins | should -be 70
        }
        It 'ADDemographics.ps1 script exists' {
            Test-Path -path $basePath\SEC557Labs\Lab3.3\ADDemographics.ps1 -Pathtype Leaf | Should -beTrue
        }
        It 'AD.json exists' {
            Test-Path -path $basePath\SEC557Labs\Lab3.3\AD.json -Pathtype Leaf | Should -beTrue
        }
        
    }
    Context 'Lab3.4'{
        #Lab prep
        BeforeAll{
            $password = ConvertTo-SecureString 'Password1!' -AsPlainText -Force
            $cred = New-Object System.Management.Automation.PSCredential ('auditor', $password)
            Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -Confirm:$false
            Set-PowerCLIConfiguration -Scope User -DefaultVIServerMode Single -Confirm:$false
            Connect-VIServer -Server esxi1 -Credential $cred

            $ntpStatus = (Get-VMHost | Sort Name | Select Name,  `
                @{N="NTPServer"; E={$_ | Get-VMHostNtpServer}}, `
                @{N="ServiceRunning"; E={(Get-VmHostService -VMHost $_ |  
                    Where-Object {$_.key-eq "ntpd"} ).Running}}, `
                @{N="Policy"; E={(Get-VmHostService -VMHost $_ |  
                        Where-Object {$_.key-eq "ntpd"} ).Policy}}, `
                @{N="ServiceRequired"; E={(Get-VmHostService -VMHost $_ |  
                    Where-Object {$_.key-eq "ntpd"} ).Required}})
        }
        #Get back to the initial state for lab 3.4
        AfterAll {
            Set-PowerCLIConfiguration -scope user -InvalidCertificateAction Unset -Confirm:$false
        }
        
        It 'Get-VM returns 2 results'{
            Get-VM | Should -HaveCount 2
        }

        It 'DNS addresses for VMHost are correct' {
            (Get-VMHost).ExtensionData.Config.Network.DNSConfig.Address | 
                Should -Contain '8.8.8.8'
            (Get-VMHost).ExtensionData.Config.Network.DNSConfig.Address | 
                Should -Contain '10.50.7.253'
        }

        It 'NTP server is pool.ntp.org' {
            $ntpStatus.NTPServer | Should -Be 'pool.ntp.org'
        }

        It 'NTP Policy is OFF' {
            $ntpStatus.Policy | Should -Be "off"
        }

        It 'NTP Running is false' {
            $ntpStatus.ServiceRunning | Should -BeFalse
        }

        It 'NTP Required is false' {
            $ntpStatus.ServiceRequired | Should -BeFalse
        }

        It 'Patch count is 76' {
            (Get-ESXCli -Server esxi1).software.vib.list() | Should -HaveCount 76
        }

        It 'Datastore version is > 6' {
            (Get-VMHost -Server esxi1 | Get-Datastore).FileSystemVersion | 
                Should -BeGreaterOrEqual 6.0
        }

        It 'VMWare version is correct' {
            $uri = "https://kb.vmware.com/services/apexrest/v1/article?docid=2143832&lang=en_us"
            (Invoke-WebRequest -UseBasicParsing -Uri $uri).content | out-file .\page.json
            $source = (Get-Content .\page.json | ConvertFrom-Json).Content[1].Resolution
            #Create an HTML object
            $html = New-Object -ComObject "HTMLFile"
            $html.write([System.Text.Encoding]::Unicode.GetBytes($source))
            $tables = $html.getElementsByTagName('Table')
            $esxiVersions = @()

            #Grab rows in the table (except the first one) and put them in the $esxiVersions variable
            foreach( $row in ($tables[0].rows | Select-Object -Skip 1) ){
            #Don't process the row at the bottom of the table with no date
                if( $row.cells[2].innerText -match "^\d+" ){
                    $versionResult = [PSCustomObject]@{
                    Version = $row.cells[0].innerText
                    Product = ($row.cells[0].innerText) -replace '(ESX[i]? [0-9]\.[0-9]).*', '$1'
                    ReleaseName = $row.cells[1].innerText
                    ReleaseDate = Get-Date -Date $row.cells[2].innerText
                    Build = [int]$row.cells[3].innerText
                    }
                    $esxiVersions += $versionResult
                }
            }
            $build = (Get-VMHost).Build
            $myVersion = $esxiVersions | Where-Object Build -eq $build 
            $myVersion.build | Should -Be 17867351
        }

        It 'Compliance.json exists' {
            Test-Path -path $basePath\SEC557Labs\Lab3.5\Compliance.json -Pathtype Leaf | Should -beTrue
        }

       #TODO: Replicate the passing pester tests from the Lab3.4\Esxi.Tests.ps1 
       #and use -not in the others to make them pass.This will save having to save 
       #the ESXi credentials in the secret vault just so the pester tests can run


       #Inspec testing is done from the Ubuntu host and will be tested there
    }
    
    #Lab3.5 is done from the Ubuntu host
    Context 'Lab3.6'{
        It 'OSQuery has at least 100 tables'{
            (osqueryi ".tables").Count | Should -BeGreaterOrEqual 100
        }
        It 'OSQuery returns firefox in programs table' {
            (osqueryi "select name from programs;" --json | convertFrom-Json) | 
            Where-Object name -like '*firefox*' | Should -HaveCount 1
        }
        It 'Osquery Local Admins returns two users' {
            $res = (osqueryi "select username, groupname, type from users join user_groups on user_groups.UID = users.uid join groups on groups.gid = user_groups.gid where groups.groupname ='Administrators';" --json | ConvertFrom-Json).count
            $res | Should -BeGreaterOrEqual 2
        }
    }
    Context 'Lab4.1'{
    }
    Context 'Lab4.2'{
    }
    Context 'Lab4.3'{
    }
    Context 'Lab4.4'{
    }
    Context 'Lab5.1'{
    }
    Context 'Lab5.2'{
    }

    Context 'Lab5.3'{
    }
    Context 'Lab5.4'{
    }
    Context 'CapStone'{
    }
    
}

