#Requires -RunAsAdministrator

#TODO: Do osquery tests for each test instead of saving in variable

Describe 'Acceptance Testing for Win10 VM' {

  BeforeAll {

    if( -Not (Test-Path -Path "C:\Program Files\osquery\osqueryi.exe" -PathType Leaf))
    {
      exit
    }

    $softwarePrograms = osqueryi 'select name,version from programs;' --json | ConvertFrom-Json
    $softwareChoco = osqueryi 'select name,version from chocolatey_packages;' --json | ConvertFrom-Json

  }
    
  Context 'Folder Existence Testing' {

    It 'AUD507-Labs Directory Exists' {
      Test-Path -Path "C:\users\student\AUD507-Labs\" -PathType Container | Should -BeTrue
    }

    It 'Packer Directory Does Not Exist' {
      Test-Path -Path "C:\packer" -PathType Container | Should -BeFalse
    }

  }

  Context 'Software Existence Testing' {

    It 'Assessor-GUI.exe Exists' {
      Test-Path -Path "C:\tools\CIS-CAT\Assessor-GUI.exe" -PathType Leaf | Should -BeTrue
    }

    It 'AWS CLI Exists' {
      $softwareChoco.Name | Should -Contain "awscli"
    }

    It 'Azure CLI Exists' {
      $softwareChoco.Name | Should -Contain "azure-cli"
    }

    ## TODO: Check to see if this passes when burp is updated - don't have license to launch program
    It 'Burp Suite Professional Exists' {
      $softwarePrograms.Name | Should -Contain "Burp Suite Professional 2022.9.5"
    }

    It 'Firefox Exists' {
      $softwareChoco.Name | Should -Contain "FirefoxESR"
    }

    It 'Google Cloud SDK Exists' {
      $softwareChoco.Name | Should -Contain "gcloudsdk"
    }

    It 'Git CLI Exists' {
      $softwareChoco.Name | Should -Contain "git.install"
    }

    It 'jq Exists' {
      $softwareChoco.Name | Should -Contain "jq"
    }

    It 'OpenOffice Exists' {
      $softwareChoco.Name | Should -Contain "OpenOffice"
    }

    It 'OpenVPN Exists' {
      $softwareChoco.Name | Should -Contain "openvpn-connect"
    }

    It 'OpenOffice Exists' {
      $softwareChoco.Name | Should -Contain "OpenOffice"
    }

    It 'Osqueryd Exists' {
      ## TODO: Use Get-Service - check that it exists and that it starts automatically
      Test-Path -Path "C:\Program Files\osquery\osqueryd\osqueryd.exe" -PathType Leaf | Should -BeTrue
    }

    It 'PowerShell Core Exists' {
      $softwareChoco.Name | Should -Contain "powershell-core"
    }

    It 'Pup Exists' {
      $softwareChoco.Name | Should -Contain "pup"
    }

    It 'Pup Exists' {
      $softwareChoco.Name | Should -Contain "python3"
    }

    It 'RVTools Exists' {
      $softwareChoco.Name | Should -Contain "rvtools"
    }

    It 'SetDefaultBrowser Exists' {
      $softwareChoco.Name | Should -Contain "setdefaultbrowser"
    }

    It 'SoapUI Exists' {
      $softwareChoco.Name | Should -Contain "soapui"
    }

    It 'Sslyze.exe Exists' {
      Test-Path -Path "C:\Tools\sslyze\sslyze.exe" -PathType Leaf | Should -BeTrue
    }

    It 'Windows Terminal Exists' {
      $softwareChoco.Name | Should -Contain "microsoft-windows-terminal"
    }

    It 'Terraform Exists' {
      $softwareChoco.Name | Should -Contain "terraform"
    }

    It 'VSCode Exists' {
      $softwareChoco.Name | Should -Contain "vscode"
    }

    It 'Wget Exists' {
      $softwareChoco.Name | Should -Contain "Wget"
    }

    It 'Windows PowerShell Exists' {
      ## TODO: Move to OSQuery Check
      #Test-Path -Path "%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -PathType Leaf | Should -BeTrue
      $False | Should -BeTrue
    }

    It 'Zoomit Exists' {
      $softwareChoco.Name | Should -Contain "zoomit"
    }
  }

  Context 'Firefox Addin Testing' {  
      
    It 'Wappalyzer Exists' {
      "C:\Program Files\Mozilla Firefox\distribution\policies.json" | Should -FileContentMatch 'wappalyzer'
    } 

    It 'FoxyProxy Exists' {
      "C:\Program Files\Mozilla Firefox\distribution\policies.json" | Should -FileContentMatch 'foxyproxy'
    }

    ## TODO: Retire js??
  }

  Context 'Software Version Testing' {

    It 'PowerShell Version is 7.2.7' {
      $PSVersionTable.PSVersion.ToString() | Should -BeExactly "7.2.7"
    }

    ## TODO: read through the labs to determine which software versions are needed

  }


  Context 'File Existence Testing' {

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

    It 'ADAuditGneric.ps1 Exists' {
      (Get-FileHash -Algorithm SHA256 -Path "C:\Users\student\AUD507-Labs\scripts\ADAuditGeneric.ps1").Hash | Should -Be 'E56B7EC9BD9D722C4B8926F5F489D54CFA5BB2909E1A3AC4928D0826FC31C026'
    }

    It 'FoxyProxySettings.json Exists' {
      (Get-FileHash -Algorithm SHA256 -Path "C:\tools\FoxyProxySettings.json").Hash | Should -Be '579E84B0E0D3454488B2017D4663625B2118F6653A19DFDE52AA5AA5977C0497'
    }
    
    It 'Juice-shop.zip Exists' {
      (Get-FileHash -Algorithm SHA256 -Path "C:\Users\student\AUD507-Labs\SAST\juice-shop.zip").Hash | Should -Be '7F7C4345119DC9741323436DDE8706B562F40CC512E6FD1A94E7138BE0722414'
    }

    It 'namesLower.txt Exists' {
      (Get-FileHash -Algorithm SHA256 -Path "C:\Users\student\AUD507-Labs\injection\namesLower.txt").Hash | Should -Be 'BF10F4628090B6B2ED03A3D8C146E01A917760809754967DF751F07E66DE89D2'
    }

    It 'passwords.txt Exists' {
      (Get-FileHash -Algorithm SHA256 -Path "C:\Users\student\AUD507-Labs\injection\passwords.txt").Hash | Should -Be '0B7C7628C601D1BC4583BDE3A48FF0ED674A1A5B80B6F8427B64FDFCCA144EDA'
    }

    It 'sqliDetection.txt Exists' {
      (Get-FileHash -Algorithm SHA256 -Path "C:\Users\student\AUD507-Labs\injection\sqliDetection.txt").Hash | Should -Be '9FDCF9061D97961F6A923F8FC671E23162AC3891D98246ABFD7FDEAA5570FE51'
    }

    It 'UserRights.psm1 Exists' {
      (Get-FileHash -Algorithm SHA256 -Path "C:\users\student\AUD507-Labs\scripts\UserRights.psm1").Hash | Should -Be '4F68EE67A415A01FC52C3AB773AF91EFF4EE14D0031C3244E28E0838C8034F56'
    }
  }


  ## TODO: Check labs for more modules
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
}