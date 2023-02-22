#Requires -RunAsAdministrator

#TODO: Test that c:\packer does NOT exist

Describe 'Acceptance Testing for Win10 VM' {

    BeforeAll {
  
      if( -Not (Test-Path -Path "C:\Program Files\osquery\osqueryi.exe" -PathType Leaf))
      {
        exit
      }
  
      $softwareVersions = osqueryi 'select name,version from programs;' --json | ConvertFrom-Json
    }
  
    Context 'Folder Existence Testing' {
  
      It 'AUD507-Labs Directory Exists' {
        Test-Path -Path "C:\users\student\AUD507-Labs\" -PathType Container | Should -BeTrue
      }
  
    }
  
    Context 'Software Existence Testing' {
  
      It 'WindowsTerminal Executable Exists' {        
          (Get-ChildItem -Path 'C:\Program Files\WindowsApps\*.WindowsTerminal*\wt.exe').count | Should -Be 1
      }
  
      It 'Microsoft Visual Studio Code Exists' {
          $softwareVersions.Name | Should -Contain "Microsoft Visual Studio Code"
      }
  
      It 'Mozilla Firefox Exists' {
          $softwareVersions.Name | Should -Contain "Mozilla Firefox ESR (x64 en-US)"
      }
  
      ## TODO: Pick JQ Test, use OSQuery?
      It 'JQ Executable Exists' {
          Test-Path -Path "C:\ProgramData\chocolatey\bin\jq.exe" -PathType Leaf | Should -BeTrue
      }
  
      ## TODO: Pick JQ Test, use OSQuery?
      It 'JQ Executable Exists' {
          Get-Command jq.exe | Should -BeTrue
        }
  
      It 'Wappalyzer Exists' {
          ## TODO: Policies.json?
          $False | Should -BeTrue
      }
  
      It 'FoxyProxy Exists' {
          ## TODO: Policies.json?
          ## https://pester.dev/docs/v4/usage/assertions
          ## FileContentMatch FTW!
          $False | Should -BeTrue
      }
  
      It 'OpenOffice Executable Exists' {
          ## TODO: Change to choco
          Test-Path -Path "C:\Program Files (x86)\OpenOffice 4\program\soffice.exe" -PathType Leaf | Should -BeTrue
      }
  
      It 'PowerShell Core Exists' {
          ## TODO: Change to choco
          Test-Path -Path "C:\Program Files\PowerShell\7\pwsh.exe" -PathType Leaf | Should -BeTrue
      }
  
      It 'Windows PowerShell Exists' {
          ## TODO: Move to OSQuery Check
          Test-Path -Path "%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -PathType Leaf | Should -BeTrue
      }
  
      It 'Aws CLI Exists' {
        ## TODO: Change to choco
        $softwareVersions.Name | Should -Contain "AWS Command Line Interface v2"
      }
  
      It 'OSQueryd Service Exists' {
          ## TODO: Use Get-Service - check that it exists and that it starts automatically
          $False | Should -BeTrue
      }
  
      It 'AWSPowerShell.NetCore Exists' {
          ## TODO: Get-Module
          $False | Should -BeTrue
      }
  
      It 'Azure CLI Exists' {
          ## TODO: Change to choco
          $False | Should -BeTrue
      }
  
      ## TODO: Document that this needs to move into the Lab Repo
      It 'Assessor-GUI.exe Exists' {
        Test-Path -Path "C:\tools\CIS-CAT\Assessor-GUI.exe" -PathType Leaf | Should -BeTrue
      }
  
      ## TODO: Document that this needs to move into the Lab Repo
      It 'Sslyze.exe Exists' {
        Test-Path -Path "C:\Tools\sslyze\sslyze.exe" -PathType Leaf | Should -BeTrue
      }
  
    }
  
    Context 'Software Version Testing' {
  
      It 'PowerShell Version is 7.2.7' {
        $PSVersionTable.PSVersion.ToString() | Should -BeExactly "7.2.7"
      }
  
      ## TODO: read through the labs to determine which software versions are needed
  
    }
  
    Context 'File Existence Testing' {
  
      ##! TODO: Document that this needs to move into the Lab Repo
      It 'FoxyProxySettings.json Exists' {
        Test-Path -Path "C:\tools\FoxyProxySettings.json" -PathType Leaf | Should -BeTrue
      }
  
      It 'UserRights.psm1 Exists' {
        Test-Path -Path "C:\users\student\AUD507-Labs\scripts\UserRights.psm1" -PathType Leaf | Should -BeTrue
      }
  
      It 'ADAuditGneric.ps1 Exists' {
          Test-Path -Path "C:\Users\student\AUD507-Labs\scripts\ADAuditGeneric.ps1" -PathType Leaf | Should -BeTrue
      }
  
      It 'Juice-shop.zip Exists' {
        Test-Path -Path "C:\Users\student\AUD507-Labs\SAST\juice-shop.zip" -PathType Leaf | Should -BeTrue
      }
  
      It 'sqliDetection.txt Exists' {
        Test-Path -Path "C:\Users\student\AUD507-Labs\injection\sqliDetection.txt" -PathType Leaf | Should -BeTrue
      }
  
      It 'namesLower.txt Exists' {
        Test-Path -Path "C:\Users\student\AUD507-Labs\injection\namesLower.txt" -PathType Leaf | Should -BeTrue
      }
  
      It 'passwords.txt Exists' {
        Test-Path -Path "C:\Users\student\AUD507-Labs\injection\passwords.txt" -PathType Leaf | Should -BeTrue
      }
  
    }
  
    Context 'File Integrity Testing' {
  
      It 'FoxyProxySettings.json Exists' {
        Get-FileHash -Path "C:\tools\FoxyProxySettings.json" | Should -Be 'a430e28d967f5eba2994938e9d427eafe9ffecb3'
      }
  
      It 'UserRights.psm1 Exists' {
        Get-FileHash -Path "C:\users\student\AUD507-Labs\scripts\UserRights.psm1" | Should -Be '71ad5e60088d6bb0c1090b48b1b533ce5be6e72d'
      }
  
      It 'ADAuditGneric.ps1 Exists' {
        Get-FileHash -Path "C:\Users\student\AUD507-Labs\scripts\ADAuditGeneric.ps1" | Should -Be 'a44aef3e0075400ce2462d59ad50bdcd186d2e2e'
      }
  
      It 'Juice-shop.zip Exists' {
        Get-FileHash -Path "C:\Users\student\AUD507-Labs\SAST\juice-shop.zip" | Should -Be '7451405de0e52ec36a591005c3c09fd24c3145c5'
      }
  
      It 'sqliDetection.txt Exists' {
        Get-FileHash -Path "C:\Users\student\AUD507-Labs\injection\sqliDetection.txt" | Should -Be 'fb014e8ade3b5b44ce05fe657381242c5d5361a5'
      }
  
      It 'namesLower.txt Exists' {
        Get-FileHash -Path "C:\Users\student\AUD507-Labs\injection\namesLower.txt" | Should -Be 'd1db7bba938e98f1c4b8ef68bbfdd6a07529d7ba'
      }
  
      It 'passwords.txt Exists' {
        Get-FileHash -Path "C:\Users\student\AUD507-Labs\injection\passwords.txt" | Should -Be 'dddd1582147e67457314099b702b8b49e98db996'
      }
  
    }
  
    Context 'PowerShell Module Existence Testing' {
  
      ## TODO: Document in spreadsheet
     
      It 'AWSPowerShell.NetCore Module Exists' {
        (Get-Module -ListAvailable -Name AWSPowerShell.NetCore).count | Should -BeGreaterOrEqual 1
      }
  
      It 'Az Module Exists' {
        (Get-Module -ListAvailable -Name Az).count | Should -BeGreaterOrEqual 1
      }
  
      It 'Az.Accounts Module Exists' {
        (Get-Module -ListAvailable -Name Az.Accounts).count | Should -BeGreaterOrEqual 1
      }
  
      It 'Az.Compute Module Exists' {
        (Get-Module -ListAvailable -Name Az.Compute).count | Should -BeGreaterOrEqual 1
      }
  
      It 'Az.ResourceGraph Module Exists' {
        (Get-Module -ListAvailable -Name Az.ResourceGraph).count | Should -BeGreaterOrEqual 1
      }
  
    }
  }