Describe 'Lab Setup tests for 507Ubuntu VM' {
    
    #Check basic network setup to ensure local and internet connectivity
    Context 'Network connectivity' {
        It 'Ping 507Win10' {
            $arpRes = (sudo arping -c 1 10.50.7.101 | awk '/transmitted/ { print $4 }')
            $arpRes | Should -BeExactly 1
        }
    }
}