# Invoke this test on Ubuntu with these commands (in pwsh):
<#
Set-Location /home/student/AUD507-Labs/pester/
$config=New-PesterConfiguration
$config.Output.Verbosity='detailed'
$config.Run.Path='./Ubuntu.acceptance.tests.ps1'
Invoke-Pester -Configuration $config
#>

## TODO: Clean up the names of the tests...TICE

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

      ## TODO: Test for john-data ?
      It 'john' {
        dpkg -l | grep -cE "john([^-])" | Should -Be 1
      }

      <# TODO: What all do I need in regards to mysql? -- /usr/bin/mysql --version | grep -ci ".*mysql.*"
      ii  mysql-client                          8.0.31-0ubuntu0.22.04.1                 all          MySQL database client (metapackage depending on the latest version)
      ii  mysql-client-8.0                      8.0.31-0ubuntu0.22.04.1                 amd64        MySQL database client binaries
      ii  mysql-client-core-8.0                 8.0.31-0ubuntu0.22.04.1                 amd64        MySQL database core client binaries
      ii  mysql-common                          5.8+1.0.8                               all          MySQL database common files, e.g. /etc/mysql/my.cnf
      ii  mysql-server                          8.0.31-0ubuntu0.22.04.1                 all          MySQL database server (metapackage depending on the latest version)
      ii  mysql-server-8.0                      8.0.31-0ubuntu0.22.04.1                 amd64        MySQL database server binaries and system database setup
      ii  mysql-server-core-8.0                 8.0.31-0ubuntu0.22.04.1                 amd64        MySQL database server binaries
      #>

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

      ## TODO: Someone stop me!!
      It 'ncat' {
        dpkg -l | grep -cE "nmap([^'])" | Should -Be 1
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