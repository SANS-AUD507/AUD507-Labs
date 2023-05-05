#Requires -RunAsAdministrator
# Invoke this test on 507Win10 with this command:
<#
Set-Location c:\users\student\Aud507-Labs\pester
$config=New-PesterConfiguration
$config.Output.Verbosity='detailed'
$config.Run.Path='.\Win10.Setup.tests.ps1'
Invoke-Pester -Configuration $config
#>

Describe 'Lab Setup tests for 507Win10 VM' {
    
  #Check basic network setup to ensure local and internet connectivity
  Context 'Network connectivity' {
    It 'Ping 507Ubuntu - HostOnly' {
        $res = Test-NetConnection -ComputerName ubuntu
        $res.PingSucceeded | Should -BeTrue
    }

    It 'Ping Google - NAT' {
        $res = Test-NetConnection -ComputerName dns.google
        $res.PingSucceeded | Should -BeTrue
    }
  }

  Context 'Local system checks' {
    It 'Drive free space > 10GB' {
        (Get-PSDrive -name c).Free | Should -BeGreaterThan 10000000000
    }
  }

  #The firefox plugins won't show up in osquery until the application has been run once, and
  #the polices.json file processed.
  Context 'Firefox plugins' {
    BeforeAll {
        $plugins = osqueryi "select * from firefox_addons;" --json 2>$null | ConvertFrom-Json
    }

    It 'Retire.js' {
        $plugins.identifier | Should -Contain '@retire.js'
    }

    It 'Wappalyzer' {
        $plugins.identifier | Should -Contain 'wappalyzer@crunchlabz.com'
    }

    It 'FoxyProxy' {
        $plugins.identifier | Should -Contain 'foxyproxy@eric.h.jung'
    }
  }

  Context 'Cloud services' {
    BeforeAll{
      Import-Module AWSPowerShell.NetCore
    }

    It '507DC is available over VPN' {
        $res = Test-NetConnection -ComputerName 507dc
        $res.PingSucceeded | Should -BeTrue
    }

    It 'AWS ARN is set' {
      (Get-STSCallerIdentity).Arn | should -BeLike 'arn*student*'
    }    
      
    It 'AWS config is set to us-east-2 region' {
      'C:\users\student\.aws\config' | should -FileContentMatch 'region = us-east-2'
    }

    It 'AWS config is set to json output' {
      'C:\users\student\.aws\config' | should -FileContentMatch 'output = json'
    }

    It 'Azure account is setup' {
      (az account show | ConvertFrom-Json).user.name | Should -BeLike 'student@*'
    }
  }

  Context 'Lab 2.3' {
    It 'Part 2 - Get-LocalGroupMember returns correct admins' {
      $res = (Get-LocalGroupMember -Group "administrators")
      $res | Should -Contain '507WIN10\Administrator'
      $res | Should -Contain '507WIN10\Student'
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
}