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
        BeforeAll {
            $localPorts = (sudo netstat -antp | awk '/LISTEN/ { print $4 }')
        }
        It 'Grafana on port 2003' {
            $localPorts | Should -Contain '0.0.0.0:2003'
        }
    }
}