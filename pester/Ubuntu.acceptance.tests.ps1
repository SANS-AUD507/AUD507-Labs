# Invoke this test on Ubuntu with these commands (in pwsh):
<#
Set-Location /home/student/AUD507-Labs/pester/
$config=New-PesterConfiguration
$config.Output.Verbosity='detailed'
$config.Run.Path='./Ubuntu.Setup.tests.ps1'
Invoke-Pester -Configuration $config
#>

Describe 'Acceptance Testing for Win10 VM' {
  
    Context 'Binary Existence Testing' {
      It 'ARPing exists' {
        $res = (/usr/sbin/arping )
        $res | Should -MatchExactly "^ARPing"
      }
    }
  }