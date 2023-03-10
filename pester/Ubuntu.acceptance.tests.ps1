Describe 'Acceptance Testing for Win10 VM' {
  
    Context 'Binary Existence Testing' {
      It 'ARPing exists' {
        $res = (/usr/sbin/arping )
        $res | Should -MatchExactly "^ARPing"
      }
    }
  }