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
            $replyCount = ((ping -n 4 dns.google | Select-String "^Reply").Count)
            $replyCount | Should -BeGreaterThan 0
        }
    }

    Context 'Local system checks' {
        It 'Drive free space > 10GB' {
            (Get-PSDrive -name c).Free | Should -BeGreaterThan 10000000000
        }
    }

    Context 'Firefox plugins' {
        BeforeAll {
            Write-Host "Starting firefox and sleeping for 10 seconds to ensure plugins are loaded"
            Start-Process -FilePath 'C:\Program Files\Mozilla Firefox\firefox.exe'
            Start-Sleep -Seconds 10
            Stop-Process -Name Firefox
            $plugins = osqueryi "select * from firefox_addons;" --json | ConvertFrom-Json
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