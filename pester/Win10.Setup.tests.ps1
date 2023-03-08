# Invoke this test on Ubuntu with this command:
# cd /home/student/AUD507-Labs/pester/ && pwsh -c "Invoke-Pester Win10.Setup.tests.ps1 -Show all"

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
        $res = Test-NetConnection -ComputerName 507dc
        $res.PingSucceeded | Should -BeTrue
    }
}