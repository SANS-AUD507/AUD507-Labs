# Invoke this test on Ubuntu with these commands (in pwsh):
<#
Set-Location /home/student/AUD507-Labs/pester/
$config=New-PesterConfiguration
$config.Output.Verbosity='detailed'
$config.Run.Path='./Ubuntu.acceptance.tests.ps1'
Invoke-Pester -Configuration $config
#>

Describe 'Acceptance Testing for Win10 VM' {
    Context 'Binary files' {
      It 'ARPing exists' {
        $res = (/usr/sbin/arping --help | grep -c "ARPing")
        $res | Should -Be 1
      }

      It 'Microk8s snap exists' {
        $res = (snap list | grep -c "^microk8s.*classic$")
        $res | Should -Be 1
      }

      It 'AWS CLI v2 exists' {
        $res = (/usr/local/bin/aws --version)
        $res | Should -Match "^aws-cli/2.*"
      }
    }

    Context 'File Existence' {
      #TODO: This may become six lines (3 for appbase and 3 for final)
      It 'Build.txt exists' {
        "/home/student/build.txt" | Should -FileContentMatch "^[0-9]{4}-.*"
        "/home/student/build.txt" | Should -FileContentMatch "^Jenkins.*"
        "/home/student/build.txt" | Should -FileContentMatch "^Github.*"
      }
      
    }
  }