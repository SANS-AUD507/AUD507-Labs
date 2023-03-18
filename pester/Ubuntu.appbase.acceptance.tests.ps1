# Invoke this test on Ubuntu with these commands (in pwsh):
<#
Set-Location /home/student/AUD507-Labs/pester/
$config=New-PesterConfiguration
$config.Output.Verbosity='detailed'
$config.Run.Path='./Ubuntu.acceptance.tests.ps1'
Invoke-Pester -Configuration $config
#>

Describe 'Acceptance Testing for Win10 VM' {
  
    Context 'Installed Packages' {
      It 'ARPing' {
        dpkg -l | grep -ci arping | Should -Be 1
      }

      ## TODO: Regex be scary.. looking for docker-ce but not docker-ce-cli or docker-ce-rootless-extras
      It 'Docker' {
        dpkg -l | grep -cE "docker-ce([^-])" | Should -Be 1
      }

      It 'Microk8s snap' {
        $res = (snap list | grep -c "^microk8s.*classic$")
        $res | Should -Be 1
      }

      It 'Graphite API' {
        dpkg -l | grep -ci graphite-api | Should -Be 1
        dpkg -l | grep -ci gunicorn | Should -Be 1
      }

      It 'CFN_nag' {
        gem list | grep -i cfn-nag | Should -Be 1
      }

      

    }

    Context 'Downloaded software' {
      It 'AWS CLI v2' {
        $res = (/usr/local/bin/aws --version)
        $res | Should -Match "^aws-cli/2.*"
      }

      It 'Azure-Cli'{
        $res = (/usr/bin/az --version | grep -c "^azure-cli.*")
        $res | Should -Be 1
      }

      It 'fleet' {
        $res = (/usr/bin/fleet version | grep -c "^fleet version.*")
        $res | Should -Be 1
      }
      
      It 'fleetctl' {
        $res = (/usr/bin/fleetctl --version | grep -ci "^fleetctl.*version.*")
        $res | Should -Be 1
      }


    }

    Context 'File Existence' {
      It 'Build.txt exists' {
        "/home/student/build.txt" | Should -FileContentMatch "^[0-9]{4}-.*"
        "/home/student/build.txt" | Should -FileContentMatch "^Jenkins.*"
        "/home/student/build.txt" | Should -FileContentMatch "^Github.*"
      }

      It 'Etc Issue'{
        "/etc/issue" | Should -FileContentMatch "'^This VM hosts.*5x7.*'"
      }
      
    }
  }