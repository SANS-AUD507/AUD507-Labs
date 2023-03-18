# Invoke this test on Ubuntu with these commands (in pwsh):
<#
Set-Location /home/student/AUD507-Labs/pester/
$config=New-PesterConfiguration
$config.Output.Verbosity='detailed'
$config.Run.Path='./Ubuntu.acceptance.tests.ps1'
Invoke-Pester -Configuration $config
#>

## TODO: Clean up the names of the tests...TICE
## TODO: Graphite Carbon?
## TODO: az upgrade message when running tests


Describe 'Acceptance Testing for Win10 VM' {
  
  Context 'Installed Packages' {
    It 'ARPing' {
      dpkg -l | grep -ci arping | Should -Be 1
    }

    ## TODO: Regex be scary..looking for docker-ce but not docker-ce-cli or docker-ce-rootless-extras
    ##       In other words..how hard did I make this? Cause I did this like 1 million times.......
    It 'Docker' {
      dpkg -l | grep -cE "docker-ce([^-])" | Should -Be 1
    }

    It 'Grafana' {
      dpkg -l | grep -ci "grafana-enterprise" | Should -Be 1
    }

    It 'Microk8s snap' {
      $res = (snap list | grep -c "^microk8s.*classic$")
      $res | Should -Be 1
    }

    It 'Graphite API' {
      dpkg -l | grep -ci graphite-api | Should -Be 1        
    }

    It 'Gunicorn' {
      dpkg -l | grep -ci gunicorn | Should -Be 1
    }

    It 'Inspec' {
      dpkg -l | grep -ci inspec | Should -Be 1
    }

    It 'john' {
      dpkg -l | grep -cE "john([^-])" | Should -Be 1
      dpkg -l | grep -cE "john-data" | Should -Be 1
    }

    It 'mysql' {
     dpkg -l | grep -cE "mysql-client([^-])" | Should -Be 1
     dpkg -l | grep -cE "mysql-server([^-])" | Should -Be 1
    }

    It 'Nessus' {
      dpkg -l | grep -ci nessus | Should -Be 1
    }

    ## TODO: This is what we call in the biz a bad call. Work with Clay to find a better way to solve this one
    It 'nginx' {
      dpkg -l | grep -cE "^ii  nginx([^-])" | Should -Be 1
    }

    It 'ncat' {
      dpkg -l | grep -cE "nmap([^'])" | Should -Be 1
    }

    It 'osquery' {
      dpkg -l | grep -ci osquery | Should -Be 1
    }      

    It 'PowerShell' {
      dpkg -l | grep -ci powershell | Should -Be 1
    }

    It 'tripwire' {
      dpkg -l | grep -ci tripwire | Should -Be 1
    }

    It 'CFN_nag' {
      gem list | grep -ci cfn-nag | Should -Be 1
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

    It 'gcloud cli' {
      $res = (/usr/bin/gcloud version | grep -ci "^Google Cloud.*")
      $res | Should -Be 1
    }

    It 'kubectl' {
      $res = (/usr/local/bin/kubectl version --client --output=yaml | grep -ci "^clientVersion.*")
      $res | Should -Be 1
    }

    ## TODO: This one was weird (the text was blue) couldn't seem to get grep to see the version info
    It 'njsscan' {
      $res = (/usr/local/bin/njsscan --help | grep -ci "njsscan version")
      $res | Should -Be 1
    }

    It 'Prowler' {
      $res = (/home/student/prowler/prowler -V | grep -ci "^Prowler.*")
      $res | Should -Be 1
    }

    It 'Terrascan' {
      $res = (/usr/local/bin/terrascan help | grep -ci "^Terrascan.*")
      $res | Should -Be 1
    }

    ## TODO: Don't like looking for a version here. Maybe look at the help?
    It 'yandiff' {
      $res = (/usr/local/bin/yandiff --version | grep -ci "^Version: 1.3$")
      $res | Should -Be 1
    }


    It 'Custodian' {
      $res = (/home/student/custodian/bin/custodian --help | grep -ci ".*Cloud Custodian - Cloud fleet management.*")
      $res | Should -Be 1
    }

    ## TODO: really not a fan of testing electricEye this way. Suggestions?
    It 'electricEye' {
      "/home/student/ElectricEye/README.md" | Should -FileContentMatch "^# ElectricEye$"
    }

  }

  Context 'File Existence' {
    #TODO: This may become six lines (3 for appbase and 3 for final)
    It 'Build.txt exists' {
      "/home/student/build.txt" | Should -FileContentMatch "^[0-9]{4}-.*"
      "/home/student/build.txt" | Should -FileContentMatch "^Jenkins.*"
      "/home/student/build.txt" | Should -FileContentMatch "^Github.*"
    }

    It 'Etc Issue'{
      "/etc/issue" | Should -FileContentMatch "^This VM hosts.*5x7.*"
    }

    It 'SSH Key'{
      "/home/student/.ssh/authorized_keys" | Should -FileContentMatch ".*student@win10.sec557.local$"
    }
    
  }


  Context 'PowerShell Module Existence' {
  
    It 'Pester' {
      (Get-Module -ListAvailable -Name Pester).count | Should -BeGreaterOrEqual 1
    }

  }
}
