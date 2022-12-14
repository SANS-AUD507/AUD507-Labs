#Requires -RunAsAdministrator

Describe 'Acceptance Testing for Win10 VM' {

  BeforeAll {

    if( -Not (Test-Path -Path "C:\Program Files\osquery\osqueryi.exe" -PathType Leaf))
    {
      exit
    }

    $softwareVersions = osqueryi 'select name,version from programs;' --json | ConvertFrom-Json
  }

  Context 'Software Existence Testing' {

    ### Test group to determine if the necessary software exists on the VM

    It 'Mozilla Firefox Exists' {
      $softwareVersions.Name | Should -Contain "Mozilla Firefox ESR (x64 en-US)"
    }

    It 'Aws CLI Exists' {
      $softwareVersions.Name | Should -Contain "AWS Command Line Interface v2"
    }

    ##! TODO: Document that this needs to move into the Lab Repo
    It 'BurpInstaller Executable Exists' {
      Test-Path -Path "C:\Users\student\Desktop\BurpInstaller.exe" -PathType Leaf | Should -BeTrue
    }

    It 'OpenOffice Executable Exists' {
      Test-Path -Path "C:\Program Files (x86)\OpenOffice 4\program\soffice.exe" -PathType Leaf | Should -BeTrue
    }

    It 'OpenOffice Calc Executable Exists' {
      Test-Path -Path "C:\Program Files (x86)\OpenOffice 4\program\scalc.exe" -PathType Leaf | Should -BeTrue
    }

    It 'WindowsTerminal Executable Exists' {

      ### This is a weird one. Windows terminal is installed as a WindowsApp and the version is in the path name :|
      ### To get around this, we look in the WindowsApps folder for any director containing '.WindowsTerminal'
      ### with a file named wt.exe. Once we have that, we make sure that Get-ChildItem returns a count of 1 file found

      (Get-ChildItem -Path 'C:\Program Files\WindowsApps\*.WindowsTerminal*\wt.exe').count | Should -Be 1
    }

    It 'JQ Executable Exists' {
      Get-Command jq.exe | Should -BeTrue
    }

    ##! TODO: Document that this needs to move into the Lab Repo
    It 'Assessor-GUI.exe Exists' {
      Test-Path -Path "C:\tools\CIS-CAT\Assessor-GUI.exe" -PathType Leaf | Should -BeTrue
    }

    ##! TODO: Document that this needs to move into the Lab Repo
    It 'Sslyze.exe Exists' {
      Test-Path -Path "C:\Tools\sslyze\sslyze.exe" -PathType Leaf | Should -BeTrue
    }

  }

  Context 'Software Version Testing' {

    It 'PowerShell Version is 7.2.7' {
      $PSVersionTable.PSVersion.ToString() | Should -BeExactly "7.2.7"
    }

    It 'OpenOffice Version is 4.1.13' {
      ($softwareVersions | Where-Object {$_.Name -eq 'OpenOffice 4.1.13'}).version | Should -BeExactly "4.113.9810"
    }

    It 'AWS CLI Version is 2.8.11.0' {
      ($softwareVersions | Where-Object {$_.Name -eq 'AWS Command Line Interface v2'}).version | Should -BeExactly "2.8.11.0"
    }

    It 'Mozilla Firefox Version is 102.4.0' {
      ($softwareVersions | Where-Object {$_.Name -eq 'Mozilla Firefox ESR (x64 en-US)'}).version | Should -BeExactly "102.4.0"
    }

    It 'JQ.exe Version is 1.0.0.0' {
      (Get-Command jq.exe).version.ToString() | Should -BeExactly "1.0.0.0"
    }

  }

  Context 'File Existence Testing' {

    ##! TODO: Document that this needs to move into the Lab Repo
    It 'FoxyProxySettings.json Exists' {
      Test-Path -Path "C:\tools\FoxyProxySettings.json" -PathType Leaf | Should -BeTrue
    }

    It 'InstalledSoftware.ps1 Exists' {
      Test-Path -Path "C:\users\student\AUD507-Labs\scripts\InstalledSoftware.ps1" -PathType Leaf | Should -BeTrue
    }

    It 'UserRights.psm1 Exists' {
      Test-Path -Path "C:\users\student\AUD507-Labs\scripts\UserRights.psm1" -PathType Leaf | Should -BeTrue
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

  Context 'Folder Existence Testing' {

    It 'AUD507-Labs Directory Exists' {
      Test-Path -Path "C:\users\student\AUD507-Labs\" -PathType Container | Should -BeTrue
    }

  }

  Context 'PowerShell Module Existence Testing' {
    
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



  #Context 'Firefox Extension Existence Testing' {

    ##! TODO: Test to see if these exist in the contents of the firefox resource file
    ##! C:\Program Files\Mozilla Firefox\distribution
    ##! Policies.json file content match

    #It 'Wappalyzer Exists' {

    #}

    #It 'FoxyProxy Exists' {

    #}

    #It 'Retire.js Exists' {

    #}

  #}

}