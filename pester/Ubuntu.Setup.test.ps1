Describe 'Lab Setup tests for 507Ubuntu VM' {
    
    #Check basic network setup to ensure local and internet connectivity
    Context 'Network connectivity' {
        It 'Ping 507Win10 - HostOnly' {
            $arpRes = (sudo arping -c 1 10.50.7.101 | awk '/transmitted/ { print $4 }')
            $arpRes | Should -BeExactly 1
        }

        It 'Ping Google - NAT' {
            $pingRes = (ping -c 4 dns.google | awk '/transmitted/ { print $4 }')
            $pingRes | Should -BeGreaterThan 0
        }
    }

    #Check that required ports are open
    Context 'Local services' {

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

        It 'Nginx BWApp' {
            $localPorts | Should -Contain '10.50.7.22:80'
        }

        It 'Nginx DVWA' {
            $localPorts | Should -Contain '10.50.7.24:80'
        }

        It 'Nginx WackPicko' {
            $localPorts | Should -Contain ''
        }

        It 'Nginx WackoPicko' {
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
}