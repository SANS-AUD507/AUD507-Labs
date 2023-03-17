#Requires -RunAsAdministrator

 

Describe 'Acceptance Testing for Win10 VM - AppBase' {

 

    BeforeAll {
  
   
  
      if( -Not (Test-Path -Path "C:\Program Files\osquery\osqueryi.exe" -PathType Leaf))
  
      {
  
        exit
  
      }
  
   
  
      $softwarePrograms = osqueryi 'select name,version from programs;' --json | ConvertFrom-Json
  
      $softwareChoco = osqueryi 'select name,version from chocolatey_packages;' --json | ConvertFrom-Json
  
   
  
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
  
        (Get-Service -Name osqueryd | Select-Object StartType).StartType | Should -BeExactly "Automatic"
  
        (Get-Service -Name osqueryd | Select-Object Status).Status | Should -BeExactly "Running"
  
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
  
   
  
      ## TODO: Retire js
  
    }
  
   
  
    Context 'Software Version Testing' {
  
   
  
      It 'PowerShell Version is 7.2.7' {
  
        $PSVersionTable.PSVersion.ToString() | Should -BeExactly "7.2.7"
  
      }
  
   
  
      ## TODO: read through the labs to determine which software versions are needed
  
   
  
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