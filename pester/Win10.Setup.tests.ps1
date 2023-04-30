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
        $plugins.name | Should -Contain 'retire.js'
    }

    It 'Wappalyzer' {
        $plugins.name | Should -Contain 'Wappalyzer - Technology profiler'
    }

    It 'FoxyProxy' {
        $plugins.name | Should -Contain 'FoxyProxy Standard'
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
}