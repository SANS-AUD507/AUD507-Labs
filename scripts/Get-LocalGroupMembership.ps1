#requires -Version 2
function Get-LocalGroupMembership
{
    <#
            .Synopsis
            Gets local group membership details.
 
            .DESCRIPTION
            The Get-LocalGroupMembership function uses Powershell remoting to find all members of local/builtin groups on remote computers. By default, the Get-LocalGroupMembership function is set to query the Administrators group of all domain joined computers.
     
            .EXAMPLE
            PS C:\> Get-LocalGroupMembership
 
            This command queries all domain-joined computers for direct members of the Administrators group using the current user's credentials.
 
            .EXAMPLE
            PS C:\> Get-LocalGroupMembership -Credential (Get-Credential)
 
            This command queries all domain-joined computers for direct members of the Administrators group using the specified credentials.
 
            .EXAMPLE
            PS C:\> Get-LocalGroupMembership | Export-csv -Path c:\GroupMembership.csv
 
            This command queries all domain-joined computers for direct members of the Administrators group using the current user's credentials. The results are then exported to a CSV file named GroupMembership.csv at the root of the C drive.
     
            .EXAMPLE
            PS C:\> Get-LocalGroupMembership -ComputerName CO-IT02
 
            This command queries a remote computer named CO-IT02 for direct members of the Administrators group using the current user's credentials.
 
            .EXAMPLE
            PS C:\> Get-LocalGroupMembership -ComputerName CO-IT07,CO-IT02 -Group 'Remote Desktop Users'
 
            This command queries a remote computer CO-IT02 & CO-IT07 using the current user's credentials for direct members of the specified local/builtin group, Remote Desktop Users.
 
            .EXAMPLE
            PS C:\>Set-Item -Path wsman:\localhost\Client\TrustedHosts -Value 172.16.0.0
     
            In this example a non-domain-joined computer local group membership is queried. First, in order to use an IP adress in the value of the ComputerName parameter, the IP address of the remote computer must be included in the WinRM TrustedHosts list on the local computer. To do so, the first command is run. Please note, this command assumes the WinRM TrustedHosts list on the local computer has not been previously set or is empty.
 
            Next, the non-domain-joined computer can now be queried. The credentials of an administrator account on the remote computer must be provided as shown in the command below.
     
 
            PS C:\>Get-LocalGroupMembership -ComputerName 172.16.0.0 -Credential Administrator
 
 
            Finally, unless otherwise needed, the IP address of the remote computer can now be removed from the WinRM TrustedHosts list on the local computer. To do so, the below command is run. Please note, the above command assumes the WinRM TrustedHosts list on the local computer has not been previously set or is empty.
 
 
            PS C:\>Clear-Item -Path wsman:\localhost\Client\TrustedHosts
 
            .NOTES
            **** A bug exists in Powershell version 5.0.10240.16384 that prevents group membership information from being returned when using the ADSI COM object. As a workaround one can use the Recursive switch of the Get-LocalGroupMembership function to obtain group membership information from computers on which this version of Powershell is installed.
 
            The Get-LocalGroupMembership function requires administrator rights on the remote computer(s) to be queried.
         
            Powershell remoting must be enabled on the remote computer to properly query group membership.
         
            If Powershell remoting is not enabled on a remote computer it can be enabled by either
            - Running Enable-PSRemoting locally or
            - By running Enable-RemotePSRemoting and specifying the name of the remote computer.
     
            .PARAMETER Group
            Specifies the local/builtin group(s) to query. The default is 'Administrators'.
     
            Type the the names of local/builtin groups to query in a comma-separated list.
 
            .PARAMETER ComputerName
            Specifies the computers on which the command runs. The default is all domain-joined computers.
     
            Type the NETBIOS name, IP address, or fully-qualified domain name of one or more computers in a comma-separated list. To specify the local computer, type the computer name, "localhost", or a dot (.).
     
            To use an IP address in the value of the ComputerName parameter, the command must include the Credential parameter. Also, the computer must be configured for HTTPS transport or the IP address of the remote computer must be included in the WinRM TrustedHosts list on the local computer. For instructions for adding a computer name to the TrustedHosts list, see "How to Add a Computer to the Trusted Host List" in about_Remote_Troubleshooting.
 
            .PARAMETER Credential
            Specifies a user account that has permission to perform this action. The default is the current user.
     
            Type a user name, such as "User01" or "Domain01\User01", or enter a variable that contains a PSCredential object, such as one generated by the Get-Credential cmdlet. When you type a user name, you will be prompted for a password.
 
    #>
    
    [cmdletbinding()]
    
    Param(
        [Parameter(Mandatory = $False,Position = 0,ValueFromPipelineByPropertyName = $True)]
        [Alias('Name')]
        [string[]]$ComputerName = (Get-ADComputer -Filter *).Name,
        
        [Parameter(Mandatory = $False)]
        [string[]]$Group = 'Administrators',
        
        [Parameter(Mandatory = $False)]
        [pscredential]$Credential = $null
    )
    
    Begin{}

    Process{
        [scriptblock]$Scriptblock = {
            $Group = $Using:Group
            $VerbosePreference = $Using:VerbosePreference
            $WarningPreference = $Using:WarningPreference
        
            Foreach($G in $Group)
            {
                If($PSVersionTable.PSVersion.Major -ge 3)
                {
                    Get-CimInstance -Query "SELECT * FROM Win32_GroupUser WHERE GroupComponent=`"Win32_Group.Domain='$env:COMPUTERNAME',Name='$G'`"" |
                    ForEach-Object -Process {
                        $_.PartComponent |
                        Select-Object -Property @{
                            n = 'Group'
                            e = {
                                $G
                            }
                        }, Domain, Name, @{
                            n = 'Class'
                            e = {
                                If($_.pstypenames[0] -match 'User')
                                {
                                    'User'
                                }
                                ElseIf($_.pstypenames[0] -match 'Group')
                                {
                                    'Group'
                                }
                            }
                        }
                    }|
                    ForEach-Object -Process{
                        $Object = $_
                        $Object.PSObject.Typenames.Insert(0,'ARTools.GroupMembership')
                        $Object
                    }
                }
                Else
                {
                    $ContainerObj = [ADSI]("WinNT://$env:COMPUTERNAME/$G,group")
                    Try
                    {
                        $ContainerObj.PSBase.Invoke('Members') | ForEach-Object -Process {
                            $Info = '' | Select-Object Group, Name, Domain, Class
                            $Info.Name = $_.GetType().InvokeMember('Name', 'GetProperty', $null, $_, $null)
                            $Info.Class = $_.GetType().InvokeMember('Class', 'GetProperty', $null, $_, $null)
                            If($Info.Name -match "^S-\d-\d+-(\d+-){1,14}\d+$")
                            {
                                $Info.Domain = $null
                            }
                            Else
                            {
                                $Info.Domain = ($_.GetType().InvokeMember('Parent', 'GetProperty', $null, $_, $null)).substring(8) -split '/' | Select-Object -Last 1
                            }
                            $Info.Group = $G
                            $Info.PSObject.Typenames.Insert(0,'ARTools.GroupMembership')
                            $Info
                        }
                    }
                    Catch
                    {
                        Write-Error -Message "Unable to query $Container group membership. $($_.Exception.InnerException.Message)"
                    }
                }
            } 
        }
        
        $InvokeArgs = @{
            ComputerName = $ComputerName
        }
    
        If($null -ne $Credential)
        {
            $InvokeArgs.Credential = $Credential
        }
        
        $InvokeArgs.ComputerName = Test-PSRemoting @InvokeArgs -WarningAction $WarningPreference
        
        If($null -eq $InvokeArgs.ComputerName)
        {
            Break
        }
        
        $InvokeArgs.ScriptBlock = $Scriptblock
        
        Invoke-Command @InvokeArgs -HideComputerName
    }

    End{}
}