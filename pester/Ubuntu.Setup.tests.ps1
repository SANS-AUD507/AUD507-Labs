
#Invoke this test on Ubuntu with these commands (in pwsh):
<#
Set-Location /home/student/AUD507-Labs/pester/
$config=New-PesterConfiguration
$config.Output.Verbosity='detailed'
$config.Run.Path='./Ubuntu.Setup.tests.ps1'
Invoke-Pester -Configuration $config
#>
Describe 'Lab Setup tests for 507Ubuntu VM' {
  BeforeDiscovery {
    #arping is required for testing connectivity to Win10, which has a host firewall
    sudo apt install -y arping

    #If the AWS config files are not there, then skip the AWS tests
    if( -not ( (Test-Path -Type Leaf -Path /home/student/.aws/credentials) -or (Test-Path -Type Leaf -Path /home/student/.aws/config) ) ) {
      Write-Host "Skipping AWS tests because config files do not exist"
      $skipAWS = $true
    }
    else {
      #Skip the Cloud Services tests if there are no good AWS credentials
      $userARN = (aws sts get-caller-identity | jq '.Arn')
      if( $userARN -notlike '*student*'){
        Write-Host "Skipping AWS tests because config files do not exist"
        $skipAWS = $true
      }
    }

    #If the Azure configuration is not there, then skip the Azure tests
    $azSubCount = (Get-Content /home/student/.azure/azureProfile.json | ConvertFrom-Json).Subscriptions.Count
    if( $azSubCount -lt 1) {
      Write-Host "Skipping Azure tests because config files do not exist"
      $skipAzure = $true
    } 
  }

  
  #Check basic network setup to ensure local and internet connectivity
  Context 'Network connectivity' {
    It 'Ping 507Win10 - HostOnly' {
        $arpRes = (sudo arping -c 1 10.50.7.101 | awk '/transmitted/ { print $4 }')
        $arpRes | Should -BeExactly 1 -Because 'Ensure that first network adapter is set to HostOnly'
    }

    It 'Ping Google - NAT' {
        $pingRes = (ping -c 4 dns.google | awk '/transmitted/ { print $4 }')
        $pingRes | Should -BeGreaterThan 0 -Because 'Ensure that second network adapter is set to NAT '
    }
  }

  #Required ports are open
  Context 'Local TCP ports' {

    #Get a list of listening ports to use in all tests
    BeforeAll {
        $localPorts = (sudo netstat -antp | awk '/LISTEN/ { print $4 }')
    }

    It 'Graphite on port 2003' {
        $localPorts | Should -Contain '0.0.0.0:2003' 
    }

    It 'Grafana on port 3000' {
        $localPorts | Should -Contain ':::3000' 
    }

    It 'Default Nginx site HTTP/HTTPS' {
        $localPorts | Should -Contain '10.50.7.50:80'
        $localPorts | Should -Contain '10.50.7.50:443'
    }

    #TODO: Check for port 507+content

    It 'Nginx BWApp' {
        $localPorts | Should -Contain '10.50.7.22:80'
    }

    It 'Nginx DVWA' {
        $localPorts | Should -Contain '10.50.7.24:80'
    }

    It 'Nginx WackPicko' {
        $localPorts | Should -Contain '10.50.7.23:80'
    }

    It 'Nginx Juice Shop HTTP/HTTPS' {
        $localPorts | Should -Contain '10.50.7.20:80'
        $localPorts | Should -Contain '10.50.7.20:443'
    }

    It 'Nessus' {
        $localPorts | Should -Contain '10.50.7.29:8834'
    }
  }

  #Look for appropriate content on class websites
  Context 'Websites' {
    It 'Grafana login form' {
        #look for "Grafana" in the login page
        $res = (curl -s http://localhost:3000/login | grep -ci 'grafana')
        $res | Should -BeGreaterThan 0
    }

    It 'Default website has workbook link' {
        $res = (curl -s http://10.50.7.50:80 | grep -ci workbook)
        $res | Should -BeExactly 1  
    }

    It 'Workbook website has lab links' {
        $res = (curl -s http://10.50.7.50:80/workbook/ | grep -ci " lab [0-9]\.[0-9]")
        $res | Should -BeGreaterThan 10
    }

    It 'BWapp database install' {
        $res = (curl -s  http://10.50.7.22/install.php?install=yes | grep -ci bwapp)
        $res | Should -BeGreaterThan 0
    }


    It 'DVWA login page' {
        $res = (curl -s http://10.50.7.24:80/login.php | grep -ci dvwa)
        $res | Should -BeGreaterThan 0
    }
    
    It 'WackoPicko front page' {
        $res = (curl -s http://10.50.7.23:80 | grep -ci wackopicko)
        $res | Should -BeGreaterThan 0
    }

    It 'Juice Shop front page HTTP' {
        $res = (curl -s http://10.50.7.20:80 | grep -ci juice)
        $res | Should -BeGreaterThan 0
    }

    It 'Juice Shop front page HTTPS' {
        $res = (curl -s -k https://10.50.7.20:443 | grep -ci juice)
        $res | Should -BeGreaterThan 0
    }

    It 'Nessus startup page' {
        $res = (curl -s -k https://10.50.7.29:8834 | grep -ci nessus)
        $res | Should -BeGreaterThan 0
    }
  }

  #Ensure systemd services are running
  Context 'Systemd services' {
    
    It 'Carbon cache' {
        $res = (systemctl --no-pager status carbon-cache.service | grep -ci "active (running)")
        $res | should -BeExactly 1
    }

    #Known broken in the I01 version of the VM
    # It 'Graphite-api' {
    #     $res = (systemctl --no-pager status graphite-api.service | grep -ci "active (running)")
    #     $res | should -BeExactly 1
    # }

    It 'Nginx' {
        $res = (systemctl --no-pager status nginx.service | grep -ci "active (running)")
        $res | should -BeExactly 1
    }

    It 'Microk8s kubelite' {
        $res = (systemctl --no-pager status snap.microk8s.daemon-kubelite.service | grep -ci "active (running)")
        $res | should -BeExactly 1
    }

    It 'Grafana' {
        $res = (systemctl --no-pager status  grafana-server.service | grep -ci "active (running)")
        $res | should -BeExactly 1
    }
  }

  #Check k8s services for appropriate published TCP ports
  Context 'Kubernetes TCP Ports' {
    BeforeAll {
        $k8sServices = (microk8s kubectl get services | awk '/NodePort/ { print $5 }')
    }

    It 'juice-shop' {
        $k8sServices | Should -Contain '8000:30020/TCP'
    }

    It 'dvwa' {
        $k8sServices | Should -Contain '8000:30024/TCP'
    }

    It 'bwapp' {
        $k8sServices | Should -Contain '8000:30022/TCP'
    }

    It 'wackopicko' {
        $k8sServices | Should -Contain '8000:30023/TCP'
    }
  }

  Context 'Kubernetes Pod Status' {
    It 'juice-shop' {
        $state = (microk8s kubectl get pods | awk '/juice-shop/ {print $3}')
        $state | Should -Be 'Running'
    }

    It 'dvwa' {
        $state = (microk8s kubectl get pods | awk '/dvwa/ {print $3}')
        $state | Should -Be 'Running'
    }

    It 'bwapp' {
        $state = (microk8s kubectl get pods | awk '/bwapp/ {print $3}')
        $state | Should -Be 'Running'
    }

    It 'wackopicko' {
        $state = (microk8s kubectl get pods | awk '/wackopicko/ {print $3}')
        $state | Should -Be 'Running'
    }
  }

  #Local system checks
  Context 'Local system' {
    It 'Disk Used < 75%' {
        $usedPct = [int32](df -h | awk '/ \/$/ { print $5 }' | sed -e 's/%//')
        $usedPct | should -BeLessThan 75
    }
  }

  #Check that cloud credenitals/configs can return results
  Context 'Cloud CLI configuration - AWS' -skip:$skipAWS {
    It 'AWS credentials are working' {
      $arn = aws sts get-caller-identity | awk '/Arn/ {print $2}'
      $arn | Should -BeLike '*arn*'
  }

  It 'AWS config is set to us-east-2 region' {
    '/home/student/.aws/config' | should -FileContentMatch 'region = us-east-2'
    }

    It 'AWS config is set to json output' {
    '/home/student/.aws/config' | should -FileContentMatch 'output = json'
    }
  } 
  Context 'Cloud CLI configuration - Azure' -skip:$skipAzure {
    It 'Azure credentials are working' {
        $username = (az account show | jq '.user.name')
        $username | Should -BeLike '"student@*'
    }
  }
}