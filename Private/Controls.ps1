$AuditPolicies =
@(
    @{
        Name = 'Account Lockout'
        Expected = 'Failure'
    }
    @{
        Name = 'Application Group Management'
        Expected = 'Success and Failure'
    }
    @{
        Name = 'Audit Policy Change'
        Expected = 'Success'
    }
    @{
        Name = 'Authentication Policy Change'
        Expected = 'Success'
    }
    @{
        Name = 'Authorization Policy Change'
        Expected = 'Success'
    }
    @{
        Name = 'Credential Validation'
        Expected = 'Success and Failure'
    }
    @{
        Name = 'Detailed File Share'
        Expected = 'Failure'
    }
    @{
        Name = 'File Share'
        Expected = 'Success and Failure'
    }
    @{
        Name = 'Group Membership'
        Expected = 'Success'
    }
    @{
        Name = 'IPsec Driver'
        Expected = 'Success and Failure'
    }
    @{
        Name = 'Logoff'
        Expected = 'Success'
    }
    @{
        Name = 'Logon'
        Expected = 'Success and Failure'
    }
    @{
        Name = 'MPSSVC Rule-Level Policy Change'
        Expected = 'Success and Failure'
    }
    @{
        Name = 'Other Logon/Logoff Events'
        Expected = 'Success and Failure'
    }
    @{
        Name = 'Other Object Access Events'
        Expected = 'Success and Failure'
    }
    @{
        Name = 'Other Policy Change Events'
        Expected = 'Failure'
    }
    @{
        Name = 'Other System Events'
        Expected = 'Success and Failure'
    }
    @{
        Name = 'PNP Activity'
        Expected = 'Success'
    }
    @{
        Name = 'Process Creation'
        Expected = 'Success'
    }
    @{
        Name = 'Removable Storage'
        Expected = 'Success and Failure'
    }
    @{
        Name = 'Security Group Management'
        Expected = 'Success'
    }
    @{
        Name = 'Security State Change'
        Expected = 'Success'
    }
    @{
        Name = 'Security System Extension'
        Expected = 'Success'
    }
    @{
        Name = 'Sensitive Privilege Use'
        Expected = 'Success and Failure'
    }
    @{
        Name = 'Special Logon'
        Expected = 'Success'
    }
    @{
        Name = 'System Integrity'
        Expected = 'Success and Failure'
    }
    @{
        Name = 'User Account Management'
        Expected = 'Success and Failure'
    }
)

$RegistryEntries =
@(
    @{
        Description = "Ensure 'Block Microsoft accounts' is set to 'Users can't add or log on with Microsoft accounts'"
        Category = "Accounts"
        Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        Name = "NoConnectedUser"
        Expected = 3
        Control = "{0} -eq 3"
        Rationale = "Keep control of which accounts are allowed to log onto company's workstations"
    }
    @{
        Description = "Ensure 'Limit local account use of blank passwords to console logon only' is set to 'Enabled'"
        Category = "Accounts"
        Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
        Name = "LimitBlankPasswordUse"
        Expected = 1
        Control = "{0} -eq 1"
        Rationale = "Prevent local accounts that have blank passwords to log on to the network from remote client computers"
    }
    @{
        Description = "Ensure 'Admin Approval Mode for the Built-in Administrator account' is set to 'Enabled'"
        Category = "User Account Control"
        Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        Name = "FilterAdministratorToken"
        Expected = 1
        Control = "{0} -eq 1"
        Rationale = "Ask for consent whenever a program run as the local Administrator requests an elevation of privileges"
    }
    @{
        Description = "Ensure 'Behavior of the elevation prompt for standard users' is set to 'Automatically deny elevation requests'"
        Category = "User Account Control"
        Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        Name = "ConsentPromptBehaviorUser"
        Expected = 0
        Control = "{0} -eq 0"
        Rationale = "Ask for administrative credentials whenever a program run by a user requests an elevation of privileges"
    }
    @{
        Description = "Ensure 'Detect application installations and prompt for elevation' is set to 'Enabled'"
        Category = "User Account Control"
        Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        Name = "EnableInstallerDetection"
        Expected = 1
        Control = "{0} -eq 1"
        Rationale = "Prevent malicious software installation"
    }
    @{
        Description = "Ensure 'Only elevate UIAccess applications that are installed in secure locations' is set to 'Enabled'"
        Category = "User Account Control"
        Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        Name = "EnableSecureUIAPaths"
        Expected = 1
        Control = "{0} -eq 1"
        Rationale = "Default behavior"
    }
    @{
        Description = "Ensure 'Run all administrators in Admin Approval Mode' is set to 'Enabled'"
        Category = "User Account Control"
        Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        Name = "EnableLUA"
        Expected = 1
        Control = "{0} -eq 1"
        Rationale = "Turn on UAC (User Account Control)"
    }
    @{
        Description = "Ensure 'Switch to the secure desktop when prompting for elevation' is set to 'Enabled'"
        Category = "User Account Control"
        Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        Name = "PromptOnSecureDesktop"
        Expected = 1
        Control = "{0} -eq 1"
        Rationale = "Reduce the likelihood of a successful spoofing attack on the elevation prompt UI"
    }
    @{
        Description = "Ensure 'Virtualize file and registry write failures to per-user locations' is set to 'Enabled'"
        Category = "User Account Control"
        Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        Name = "EnableVirtualization"
        Expected = 1
        Control = "{0} -eq 1"
        Rationale = "Permit legacy applications only to write data to specific locations"
    }
    @{
        Category = "AutoPlay Policy"
        Description = "Ensure 'Disallow Autoplay for non-volume devices' is set to 'Enabled'"
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer"
        Name = "NoAutoplayfornonVolume"
        Expected = 1
        Control = "{0} -eq 1"
        Rationale = "Prevent malicious software to be automatically executed without user intervention"
    }
    @{
        Category = "AutoPlay Policy"
        Description = "Ensure 'Set the default behavior for AutoRun' is set to 'Enabled: Do not execute any autorun commands'"
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer"
        Name = "NoAutorun"
        Expected = 1
        Control = "{0} -eq 1"
        Rationale = "Prevent malicious software to be automatically executed without user intervention"
    }
    @{
        Category = "AutoPlay Policy"
        Description = "Ensure 'Turn off Autoplay' is set to 'Enabled: All drives'"
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer"
        Name = "NoDriveTypeAutoRun"
        Expected = 255
        Control = "{0} -eq 255"
        Rationale = "Prevent malicious software to be automatically executed without user intervention"
    }
    @{
        Category = "BitLocker"
        Description = "Ensure 'Allow enhanced PINs for startup' is set to 'Enabled'"
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
        Name = "UseEnhancedPin"
        Expected = 1
        Control = "{0} -eq 1"
        Condition = "Workstation"
        Rationale = "Increase complexity of PIN to reduce the likelihood of a successful brute-force attack"
    }
    @{
        Category = "BitLocker"
        Description = "Ensure 'Allow Secure Boot for integrity validation' is set to 'Enabled'"
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
        Name = "OSAllowSecureBootForIntegrity"
        Expected = 1
        Control = "{0} -eq 1"
        Condition = "Workstation"
        Rationale = "Prevent from booting with another operating system which would not be digitally signed"
    }
    @{
        Category = "BitLocker"
        Description = "Ensure 'Choose how BitLocker-protected operating system drives can be recovered' is set to 'Enabled'"
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
        Name = "OSRecovery"
        Expected = 1
        Control = "{0} -eq 1"
        Condition = "Workstation"
        Rationale = "Prevent from loosing system data in case the user loose his primary key"
    }
    @{
        Category = "BitLocker"
        Description = "Ensure 'Allow data recovery agent' is set to 'Enabled: False'"
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
        Name = "OSManageDRA"
        Expected = 0
        Control = "{0} -eq 0"
        Condition = "Workstation"
        Rationale = "Ensure administrators can always access encrypted data"
    }
    @{
        Category = "BitLocker"
        Description = "Ensure 'Recovery Password' is set to 'Enabled: Require 48-digit recovery password'"
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
        Name = "OSRecoveryPassword"
        Expected = 1
        Control = "{0} -eq 1"
        Condition = "Workstation"
        Rationale = "Protect recovery access with a strong authentication"
    }
    @{
        Category = "BitLocker"
        Description = "Ensure 'Recovery Key' is set to 'Enabled: Do not allow 256-bit recovery key'"
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
        Name = "OSRecoveryKey"
        Expected = 0
        Control = "{0} -eq 0"
        Condition = "Workstation"
        Rationale = "Ensure users must be domain connected to turn on BitLocker"
    }
    @{
        Category = "BitLocker"
        Description = "Ensure 'Omit recovery options from the BitLocker setup wizard' is set to 'Enabled: True'"
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
        Name = "OSHideRecoveryPage"
        Expected = 1
        Control = "{0} -eq 1"
        Condition = "Workstation"
        Rationale = "Prevent users from manually select recovery options"
    }
    @{
        Category = "BitLocker"
        Description = "Ensure 'Save BitLocker recovery information to AD DS for operating system drives' is set to 'Enabled: True'"
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
        Name = "OSActiveDirectoryBackup"
        Expected = 1
        Control = "{0} -eq 1"
        Condition = "Workstation"
        Rationale = "Ensure recovery keys are backed up to AD DS"
    }
    @{
        Category = "BitLocker"
        Description = "Ensure 'Configure storage of BitLocker recovery information to AD DS:' is set to 'Enabled: Store recovery passwords and key packages'"
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
        Name = "OSActiveDirectoryInfoToStore"
        Expected = 1
        Control = "{0} -eq 1"
        Condition = "Workstation"
        Rationale = "Ensure both recovery passwords and key packages are backed up to AD DS"
    }
    @{
        Category = "BitLocker"
        Description = "Ensure 'Do not enable BitLocker until recovery information is stored to AD DS for operating system drives' is set to 'Enabled: True'"
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
        Name = "OSRequireActiveDirectoryBackup"
        Expected = 1
        Control = "{0} -eq 1"
        Condition = "Workstation"
        Rationale = "Ensure users are domain connected and recovery information are backed up to enable BitLocker"
    }
    @{
        Category = "BitLocker"
        Description = "Ensure 'Configure use of hardware-based encryption for operating system drives' is set to 'Disabled'"
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
        Name = "OSHardwareEncryption"
        Expected = 0
        Control = "{0} -eq 0"
        Condition = "Workstation"
        Rationale = "Mitigate vulnerabilities introduced by certain self-encrypting drives (SEDs)"
    }
    @{
        Category = "BitLocker"
        Description = "Ensure 'Configure use of passwords for operating system drives' is set to 'Disabled'"
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
        Name = "OSPassphrase"
        Expected = 0
        Control = "{0} -eq 0"
        Condition = "Workstation"
        Rationale = "Prevent from brute-force or dictionnary attacks"
    }
    @{
        Category = "BitLocker"
        Description = "Ensure 'Require additional authentication at startup' is set to 'Enabled'"
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
        Name = "UseAdvancedStartup"
        Expected = 1
        Control = "{0} -eq 1"
        Condition = "Workstation"
        Rationale = "Increase the protection of the TPM in case the computer is lost or stolen"
    }
    @{
        Category = "BitLocker"
        Description = "Ensure 'Allow BitLocker without a compatible TPM' is set to 'Enabled: False'"
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
        Name = "EnableBDEWithNoTPM"
        Expected = 0
        Control = "{0} -eq 0"
        Condition = "Workstation"
        Rationale = "Ensure the TPM is compatible to use BitLocker"
    }
    @{
        Category = "BitLocker"
        Description = "Ensure 'Configure TPM startup:' is set to 'Enabled: Do not allow TPM'"
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
        Name = "UseTPM"
        Expected = 0
        Control = "{0} -eq 0"
        Condition = "Workstation"
        Rationale = "Ensure the TPM alone is not sufficient to use BitLocker"
    }
    @{
        Category = "BitLocker"
        Description = "Ensure 'Configure TPM startup PIN:' is set to 'Enabled: Require startup PIN with TPM'"
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
        Name = "UseTPMPIN"
        Expected = 1
        Control = "{0} -eq 1"
        Condition = "Workstation"
        Rationale = "Ensure a PIN is required in addition to a TPM for BitLocker authentication"
    }
    @{
        Category = "BitLocker"
        Description = "Ensure 'Configure TPM startup key:' is set to 'Enabled: Do not allow startup key with TPM'"
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
        Name = "UseTPMKey"
        Expected = 0
        Control = "{0} -eq 0"
        Condition = "Workstation"
        Rationale = "Prevent from startup key usage for BitLocker authentication"
    }
    @{
        Category = "BitLocker"
        Description = "Ensure 'Configure TPM startup key and PIN:' is set to 'Enabled: Do not allow startup key and PIN with TPM'"
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
        Name = "UseTPMKeyPIN"
        Expected = 0
        Control = "{0} -eq 0"
        Condition = "Workstation"
        Rationale = "Prevent from startup key and PIN combination for BitLocker authentication"
    }
    @{
        Category = "Devices"
        Description = "Ensure 'Prevent users from installing printer drivers' is set to 'Enabled'"
        Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers"
        Name = "AddPrinterDrivers"
        Expected = 1
        Control = "{0} -eq 1"
        Rationale = "Prevent users installing malicious drivers"
    }
    @{
        Category = "System Services"
        Description = "Ensure 'IIS Admin Service (IISADMIN)' is set to 'Disabled' or 'Not Installed'"
        Path = "HKLM:\SYSTEM\CurrentControlSet\Services\IISADMIN"
        Name = "Start"
        Expected = "4 or not found"
        Control = "{0} -eq 4 -or {0} -eq 'Not found'"
        Condition = "Workstation"
        Rationale = "Workstation should not host websites"
    }
    @{
        Category = "System Services"
        Description = "Ensure 'Geolocation Service (lfsvc)' is set to 'Disabled'"
        Path = "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc"
        Name = "Start"
        Expected = 4
        Control = "{0} -eq 4"
        Rationale = "Prevent from revealing the computer location"
    }
    @{
        Category = "System Services"
        Description = "Ensure 'Xbox Live Auth Manager (XblAuthManager)' is set to 'Disabled'"
        Path = "HKLM:\SYSTEM\CurrentControlSet\Services\XblAuthManager"
        Name = "Start"
        Expected = 4
        Control = "{0} -eq 4"
        Rationale = "Disable a gaming service which has no place in an enterprise context"
    }
    @{
        Category = "System Services"
        Description = "Ensure 'Downloaded Maps Manager (MapsBroker)' is set to 'Disabled'"
        Path = "HKLM:\SYSTEM\CurrentControlSet\Services\MapsBroker"
        Name = "Start"
        Expected = 4
        Control = "{0} -eq 4"
        Rationale = "Prevent from revealing the computer location and automatic downloads"
    }
    @{
        Category = "System Services"
        Description = "Ensure 'Computer Browser (Browser)' is set to 'Disabled' or 'Not Installed'"
        Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Browser"
        Name = "Start"
        Expected = "4 -or not found"
        Control = "{0} -eq 4 -or {0} -eq 'Not found'"
        Rationale = "Prevent from exposing a list of computers and their network shares"
    }
    @{
        Category = "System Services"
        Description = "Ensure 'Bluetooth Support Service (bthserv)' is set to 'Disabled'"
        Path = "HKLM:\SYSTEM\CurrentControlSet\Services\bthserv"
        Name = "Start"
        Expected = 4
        Control = "{0} -eq 4"
        Rationale = "Disable Bluetooth technology, which has inherent security risks such has weak or no encryption"
    }
    @{
        Category = "System Services"
        Description = "Ensure 'Bluetooth Audio Gateway Service (BTAGService)' is set to 'Disabled'"
        Path = "HKLM:\SYSTEM\CurrentControlSet\Services\BTAGService"
        Name = "Start"
        Expected = 4
        Control = "{0} -eq 4"
        Rationale = "Disable Bluetooth technology, which has inherent security risks such has weak or no encryption"
    }
    @{
        Category = "System Services"
        Description = "Ensure 'Infrared monitor service (irmon)' is set to 'Disabled' or 'Not Installed'"
        Path = "HKLM:\SYSTEM\CurrentControlSet\Services\irmon:Start"
        Expected = "4 or not found"
        Control = "{0} -eq 4 -or {0} -eq 'Not found'"
        Rationale = "Disable infrared file transfers"
    }
    @{
        Category = "System Services"
        Description = "Ensure 'Internet Connection Sharing (ICS) (SharedAccess)' is set to 'Disabled'"
        Path = "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess"
        Name = "Start"
        Expected = 4
        Control = "{0} -eq 4"
        Rationale = "Prevent from turning the computer into an Internet router, that could be abused for lateralization"
    }
    @{
        Category = "System Services"
        Description = "Ensure 'Link-Layer Topology Discovery Mapper (lltdsvc)' is set to 'Disabled'"
        Path = "HKLM:\SYSTEM\CurrentControlSet\Services\lltdsvc"
        Name = "Start"
        Expected = 4
        Control = "{0} -eq 4"
        Rationale = "Reduce the ability to discover the network topology"
    }
    @{
        Category = "System Services"
        Description = "Ensure 'LxssManager (LxssManager)' is set to 'Disabled' or 'Not Installed'"
        Path = "HKLM:\SYSTEM\CurrentControlSet\Services\LxssManager"
        Name = "Start"
        Expected = "4 or not found"
        Control = "{0} -eq 4 -or {0} -eq 'Not found'"
        Rationale = "Disable the Linux Subsystem and prevent from malicious ELF binaries injection"
    }
    @{
        Category = "System Services"
        Description = "Ensure 'Microsoft FTP Service (FTPSVC)' is set to 'Disabled' or 'Not Installed'"
        Path = "HKLM:\SYSTEM\CurrentControlSet\Services\FTPSVC"
        Name = "Start"
        Expected = "4 or not found"
        Control = "{0} -eq 4 -or {0} -eq 'Not found'"
        Condition = "Workstation"
        Rationale = "Workstation should not host FTP servers"
    }
    @{
        Category = "System Services"
        Description = "Ensure 'Microsoft iSCSI Initiator Service (MSiSCSI)' is set to 'Disabled'"
        Path = "HKLM:\SYSTEM\CurrentControlSet\Services\MSiSCSI"
        Name = "Start"
        Expected = 4
        Control = "{0} -eq 4"
        Condition = "Workstation"
        Rationale = "Prevent from iSCSI usage which use a very weak authentication protocol (CHAP)"
    }
    @{
        Category = "System Services"
        Description = "Ensure 'OpenSSH SSH Server (sshd)' is set to 'Disabled' or 'Not Installed'"
        Path = "HKLM:\SYSTEM\CurrentControlSet\Services\sshd"
        Name = "Start"
        Expected = "4 or not found"
        Control = "{0} -eq 4 -or {0} -eq 'Not found'"
        Condition = "Workstation"
        Rationale = "Workstation should not host SSH servers"
    }
    @{
        Category = "System Services"
        Description = "Ensure 'Peer Name Resolution Protocol (PNRPsvc)' is set to 'Disabled'"
        Path = "HKLM:\SYSTEM\CurrentControlSet\Services\PNRPsvc"
        Name = "Start"
        Expected = 4
        Control = "{0} -eq 4"
        Rationale = "Prevent peer-to-peer name resolution"
    }
    @{
        Category = "System Services"
        Description = "Ensure 'Peer Networking Grouping (p2psvc)' is set to 'Disabled'"
        Path = "HKLM:\SYSTEM\CurrentControlSet\Services\p2psvc"
        Name = "Start"
        Expected = 4
        Control = "{0} -eq 4"
        Rationale = "Prevent peer-to-peer name resolution"
    }
    @{
        Category = "System Services"
        Description = "Ensure 'Peer Networking Identity Manager (p2pimsvc)' is set to 'Disabled'"
        Path = "HKLM:\SYSTEM\CurrentControlSet\Services\p2pimsvc"
        Name = "Start"
        Expected = 4
        Control = "{0} -eq 4"
        Rationale = "Prevent peer-to-peer name resolution"
    }
    @{
        Category = "System Services"
        Description = "Ensure 'PNRP Machine Name Publication Service (PNRPAutoReg)' is set to 'Disabled'"
        Path = "HKLM:\SYSTEM\CurrentControlSet\Services\PNRPAutoReg"
        Name = "Start"
        Expected = 4
        Control = "{0} -eq 4"
        Rationale = "Prevent peer-to-peer name resolution"
    }
    @{
        Category = "System Services"
        Description = "Ensure 'Print Spooler (Spooler)' is set to 'Disabled'"
        Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Spooler"
        Name = "Start"
        Expected = 4
        Control = "{0} -eq 4"
        Rationale = "Mitigate the PrintNightmare vulnerability [CVE-2021-34527]"
    }
    @{
        Category = "System Services"
        Description = "Ensure 'Problem Reports and Solutions Control Panel Support (wercplsupport)' is set to 'Disabled'"
        Path = "HKLM:\SYSTEM\CurrentControlSet\Services\wercplsupport"
        Name = "Start"
        Expected = 4
        Control = "{0} -eq 4"
        Rationale = "Prevent from disclosing sensitive information to Microsoft"
    }
    @{
        Category = "System Services"
        Description = "Ensure 'Remote Access Auto Connection Manager (RasAuto)' is set to 'Disabled'"
        Path = "HKLM:\SYSTEM\CurrentControlSet\Services\RasAuto"
        Name = "Start"
        Expected = 4
        Control = "{0} -eq 4"
        Rationale = "Prevent systems from initiating dial connections without user consent"
    }
    @{
        Category = "System Services"
        Description = "Ensure 'Remote Desktop Configuration (SessionEnv)' is set to 'Disabled'"
        Path = "HKLM:\SYSTEM\CurrentControlSet\Services\SessionEnv"
        Name = "Start"
        Expected = 4
        Control = "{0} -eq 4"
        Condition = "Workstation"
        Rationale = "Disable Remote Desktop connections on workstations"
    }
    @{
        Category = "System Services"
        Description = "Ensure 'Remote Desktop Services (TermService)' is set to 'Disabled'"
        Path = "HKLM:\SYSTEM\CurrentControlSet\Services\TermService"
        Name = "Start"
        Expected = 4
        Control = "{0} -eq 4"
        Rationale = "Disable Remote Desktop connections on workstations"
    }
    @{
        Category = "System Services"
        Description = "Ensure 'Remote Desktop Services UserMode Port Redirector (UmRdpService)' is set to 'Disabled'"
        Path = "HKLM:\SYSTEM\CurrentControlSet\Services\UmRdpService"
        Name = "Start"
        Expected = 4
        Control = "{0} -eq 4"
        Rationale = "Disable Remote Desktop connections on workstations"
    }
    @{
        Category = "System Services"
        Description = "Ensure 'Remote Procedure Call (RPC) Locator (RpcLocator)' is set to 'Disabled'"
        Path = "HKLM:\SYSTEM\CurrentControlSet\Services\RpcLocator"
        Name = "Start"
        Expected = 4
        Control = "{0} -eq 4"
        Rationale = "Disable legacy service that should be enabled only for a specific old application compatibility"
    }
    @{
        Category = "System Services"
        Description = "Ensure 'Remote Registry (RemoteRegistry)' is set to 'Disabled'"
        Path = "HKLM:\SYSTEM\CurrentControlSet\Services\RemoteRegistry"
        Name = "Start"
        Expected = 4
        Control = "{0} -eq 4"
        Rationale = "Prevent remote access to the registry"
    }
    @{
        Category = "System Services"
        Description = "Ensure 'Routing and Remote Access (RemoteAccess)' is set to 'Disabled'"
        Path = "HKLM:\SYSTEM\CurrentControlSet\Services\RemoteAccess"
        Name = "Start"
        Expected = 4
        Control = "{0} -eq 4"
        Condition = "Workstation"
        Rationale = "Workstation should not be used as Windows router"
    }
    @{
        Category = "System Services"
        Description = "Ensure 'Server (LanmanServer)' is set to 'Disabled'"
        Path = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer"
        Name = "Start"
        Expected = 4
        Control = "{0} -eq 4"
        Condition = "Workstation"
        Rationale = "Workstation should not be considered as a server, but only as a client"
    }
    @{
        Category = "System Services"
        Description = "Ensure 'Simple TCP/IP Services (simptcp)' is set to 'Disabled' or 'Not Installed'"
        Path = "HKLM:\SYSTEM\CurrentControlSet\Services\simptcp"
        Name = "Start"
        Expected = "4 or not found"
        Control = "{0} -eq 4 -or {0} -eq 'Not found'"
        Rationale = "Reduce the risk of successful attacks on the TCP/IP stack"
    }
    @{
        Category = "System Services"
        Description = "Ensure 'SNMP Service (SNMP)' is set to 'Disabled' or 'Not Installed'"
        Path = "HKLM:\SYSTEM\CurrentControlSet\Services\SNMP"
        Name = "Start"
        Expected = "4 or not found"
        Control = "{0} -eq 4 -or {0} -eq 'Not found'"
        Rationale = "Reduce the attack surface"
    }
    @{
        Category = "System Services"
        Description = "Ensure 'Special Administration Console Helper (sacsvr)' is set to 'Disabled' or 'Not Installed'"
        Path = "HKLM:\SYSTEM\CurrentControlSet\Services\sacsvr"
        Name = "Start"
        Expected = "4 or not found"
        Control = "{0} -eq 4 -or {0} -eq 'Not found'"
        Rationale = "Prevent the use of a remotely accessible command prompt aimed for remote management tasks"
    }
    @{
        Category = "System Services"
        Description = "Ensure 'SSDP Discovery (SSDPSRV)' is set to 'Disabled'"
        Path = "HKLM:\SYSTEM\CurrentControlSet\Services\SSDPSRV"
        Name = "Start"
        Expected = 4
        Control = "{0} -eq 4"
        Rationale = "Prevent the use of UPnP that allows automatic discovery and attachment to network devices"
    }
    @{
        Category = "System Services"
        Description = "Ensure 'UPnP Device Host (upnphost)' is set to 'Disabled'"
        Path = "HKLM:\SYSTEM\CurrentControlSet\Services\upnphost"
        Name = "Start"
        Expected = 4
        Control = "{0} -eq 4"
        Rationale = "Prevent the use of UPnP that allows automatic discovery and attachment to network devices"
    }
    @{
        Category = "System Services"
        Description = "Ensure 'Web Management Service (WMSvc)' is set to 'Disabled' or 'Not Installed'"
        Path = "HKLM:\SYSTEM\CurrentControlSet\Services\WMSvc"
        Name = "Start"
        Expected = "4 or not found"
        Control = "{0} -eq 4 -or {0} -eq 'Not found'"
        Rationale = "Reduce attack surface by disabling remote web management for IIS"
    }
    @{
        Category = "System Services"
        Description = "Ensure 'Windows Error Reporting Service (WerSvc)' is set to 'Disabled'"
        Path = "HKLM:\SYSTEM\CurrentControlSet\Services\WerSvc"
        Name = "Start"
        Expected = 4
        Control = "{0} -eq 4"
        Rationale = "Prevent error reporting to Microsoft"
    }
    @{
        Category = "System Services"
        Description = "Ensure 'Windows Event Collector (Wecsvc)' is set to 'Disabled'"
        Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Wecsvc"
        Name = "Start"
        Expected = 4
        Control = "{0} -eq 4"
        Rationale = "Prevent from subscriptions from remote sources that support WS-Management protocol"
    }
    @{
        Category = "System Services"
        Description = "Ensure 'Windows Media Player Network Sharing Service (WMPNetworkSvc)' is set to 'Disabled' or 'Not Installed'"
        Path = "HKLM:\SYSTEM\CurrentControlSet\Services\WMPNetworkSvc"
        Name = "Start"
        Expected = "4 or not found"
        Control = "{0} -eq 4 -or {0} -eq 'Not found'"
        Rationale = "Disable a useless service in an enterprise context"
    }
    @{
        Category = "System Services"
        Description = "Ensure 'Windows Mobile Hotspot Service (icssvc)' is set to 'Disabled'"
        Path = "HKLM:\SYSTEM\CurrentControlSet\Services\icssvc"
        Name = "Start"
        Expected = 4
        Control = "{0} -eq 4"
        Rationale = "Prevent the computer to act as a mobile hotspot, which could expose the enterprise network"
    }
    @{
        Category = "System Services"
        Description = "Ensure 'Windows Push Notifications System Service (WpnService)' is set to 'Disabled'"
        Path = "HKLM:\SYSTEM\CurrentControlSet\Services\WpnService"
        Name = "Start"
        Expected = 4
        Control = "{0} -eq 4"
        Rationale = "Prevent third-party notifications and updates to be send to the computer from the Internet"
    }
    @{
        Category = "System Services"
        Description = "Ensure 'Windows PushToInstall Service (PushToInstall)' is set to 'Disabled'"
        Path = "HKLM:\SYSTEM\CurrentControlSet\Services\PushToInstall"
        Name = "Start"
        Expected = 4
        Control = "{0} -eq 4"
        Rationale = "Prevent end users to install applications from Microsoft Store App"
    }
    @{
        Category = "System Services"
        Description = "Ensure 'Windows Remote Management (WS-Management) (WinRM)' is set to 'Disabled'"
        Path = "HKLM:\SYSTEM\CurrentControlSet\Services\WinRM"
        Name = "Start"
        Expected = 4
        Control = "{0} -eq 4"
        Rationale = "Reduce the attack surface by disabling a remote management service"
    }
    @{
        Category = "System Services"
        Description = "Ensure 'World Wide Web Publishing Service (W3SVC)' is set to 'Disabled' or 'Not Installed'"
        Path = "HKLM:\SYSTEM\CurrentControlSet\Services\W3SVC"
        Name = "Start"
        Expected = "4 or not found"
        Control = "{0} -eq 4 -or {0} -eq 'Not found'"
        Condition = "Workstation"
        Rationale = "Workstation should not be used to host and expose website"
    }
    @{
        Category = "System Services"
        Description = "Ensure 'Xbox Accessory Management Service (XboxGipSvc)' is set to 'Disabled'"
        Path = "HKLM:\SYSTEM\CurrentControlSet\Services\XboxGipSvc"
        Name = "Start"
        Expected = 4
        Control = "{0} -eq 4"
        Rationale = "Disable a useless service in an enterprise context"
    }
    @{
        Category = "System Services"
        Description = "Ensure 'Xbox Live Game Save (XblGameSave)' is set to 'Disabled'"
        Path = "HKLM:\SYSTEM\CurrentControlSet\Services\XblGameSave"
        Name = "Start"
        Expected = 4
        Control = "{0} -eq 4"
        Rationale = "Disable a useless service in an enterprise context"
    }
    @{
        Category = "System Services"
        Description = "Ensure 'Xbox Live Networking Service (XboxNetApiSvc)' is set to 'Disabled'"
        Path = "HKLM:\SYSTEM\CurrentControlSet\Services\XboxNetApiSvc"
        Name = "Start"
        Expected = 4
        Control = "{0} -eq 4"
        Rationale = "Disable a useless service in an enterprise context"
    }
    @{
        Category = "User Account Control"
        Description = "Ensure 'User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode' is set to 'Prompt for consent on the secure desktop' or higher"
        Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System:ConsentPromptBehaviorAdmin"
        Expected = "1 or 2"
        Control = "{0} -eq 1 -or {0} -eq 2"
        Rationale = "Ensure administrator is always aware when a program attempts to elevate its privileges"
    }
    @{
        Category = "Interactive Logon"
        Description = "Ensure 'Number of previous logons to cache' is set to '0'"
        Path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
        Name = "CachedLogonCount"
        Expected = "0"
        Control = "{0} -eq 0"
        Condition = 'Server'
        Rationale = "Prevent from caching passwords locally since the server is always domain joined"
    }
    @{
        Category = "Interactive Logon"
        Description = "Ensure 'Number of previous logons to cache' is set between '2 and 4'"
        Path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
        Name = "CachedLogonCount"
        Expected = "2, 3 or 4"
        Control = "{0} -ge 2 -and {0} -le 4"
        Condition = 'Workstation'
        Rationale = "Ensure the user's password is still cached even if an administrator connects to the workstation"
    }
    @{
        Category = "LAPS"
        Description = "Ensure 'Configure password backup directory' is set to 'Enabled"
        Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS"
        Name = "BackupDirectory"
        Expected = "1 or 2"
        Control = "{0} -eq 1 -or {0} -eq 2"
        Rationale = "Prevent the use of the same password on all workstations"
    }
    @{
        Category = "LAPS"
        Description = "Ensure 'Do not allow password expiration time longer than required by policy' is set to 'Enabled'"
        Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS"
        Name = "PwdExpirationProtectionEnabled"
        Expected = 1
        Control = "{0} -eq 1"
        Rationale = "Prevent the use of the same password on all workstations"
    }
    @{
        Category = "LAPS"
        Description = "Ensure 'Enable password encryption' is set to 'Enabled'"
        Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS"
        Name = "ADPasswordEncryptionEnabled"
        Expected = 1
        Control = "{0} -eq 1"
        Rationale = "Prevent the use of the same password on all workstations"
    }
    @{
        Category = "LAPS"
        Description = "Ensure 'Password Complexity' is set to 'Enabled'"
        Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS"
        Name = "PasswordComplexity"
        Expected = 4
        Control = "{0} -eq 4"
        Rationale = "Prevent the use of the same password on all workstations"
    }
    @{
        Category = "LAPS"
        Description = "Ensure 'Password Length' is set to 'Enabled: 15 or more'"
        Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS"
        Name = "PasswordLength"
        Expected = 15
        Control = "{0} -eq 15"
        Rationale = "Prevent the use of the same password on all workstations"
    }
    @{
        Category = "LAPS"
        Description = "Ensure 'Password Age (Days)' is set to 'Enabled: 30 or fewer'"
        Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS"
        Name = "PasswordAgeDays"
        Expected = 30
        Control = "{0} -eq 30"
        Rationale = "Prevent the use of the same password on all workstations"
    }
    @{
        Category = "LAPS"
        Description = "Ensure 'Grace period (hours)' is set to 'Enabled: 8 or fewer hours, but not 0'"
        Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS"
        Name = "PostAuthenticationResetDelay"
        Expected = "8 or less, but not 0"
        Control = "{0} -le 8 -and {0} -gt 0"
        Rationale = "Prevent the use of the same password on all workstations"
    }
    @{
        Category = "LAPS"
        Description = "Ensure 'Post-authentication actions: Actions' is set to 'Enabled: Reset the password and logoff the managed account'"
        Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS"
        Name = "PostAuthenticationActions"
        Expected = "3 or 5"
        Control = "{0} -eq 3 -or {0} -eq 5"
        Rationale = "Prevent the use of the same password on all workstations"
    }
    @{
        Category = "Screen Saver"
        Description = "Ensure 'Screen Saver status' is set to 'Enabled'"
        Path = "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop"
        Name = "ScreenSaveActive"
        Expected = 1
        Control = "{0} -eq 1"
        Rationale = "Prevent physical access when the user forgot to lock his session"
    }
    @{
        Category = "Screen Saver"
        Description = "Ensure 'Screen Saver is secured' is set to 'Enabled'"
        Path = "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop"
        Name = "ScreenSaverIsSecure"
        Expected = 1
        Control = "{0} -eq 1"
        Rationale = "Enforce password authentication to unlock from screen saver"
    }
    @{
        Category = "Screen Saver"
        Description = "Ensure 'Screen Saver timeout' is set to 'Enabled'"
        Path = "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop"
        Name = "ScreenSaveTimeOut"
        Expected = 300
        Control = "{0} -eq 300"
        Rationale = "Automatically lockout the computer after 5 minutes of inactivity"
    }
    @{
        Category = "File Extension"
        Description = "Ensure 'Hide File Name Extension' is set to 'Disable'"
        Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
        Name = "HideFileExt"
        Expected = 0
        Control = "{0} -eq 0"
        Rationale = "Reveal potentially hidden malicious executables"
    }
    @{
        Category = "Mass Storage"
        Description = "Ensure 'USB Mass Storage Driver' is set to 'Disable'"
        Path = "HKLM:\SYSTEM\CurrentControlSet\Services\UsbStor"
        Name = "Start"
        Expected = 4
        Control = "{0} -eq 4"
        Rationale = "Prevent malicious mass storage devices (data exfiltration, Rubber Duccky, etc.)"
    }
    <# TODO: Check what is possible to do with Get-NetFirewallProfile cmdlet (https://learn.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewallprofile?view=windowsserver2022-ps) #>
    @{
        Category = "Firewall"
        Description = "Ensure 'Domain: Firewall state' is set to 'On'"
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile"
        Name = "EnableFirewall"
        Expected = 1
        Control = "{0} -eq 1"
        Rationale = "Reduce the attack surface of the computer over the network"
    }
    @{
        Category = "Firewall"
        Description = "Ensure 'Domain: Inbound connections' is set to 'Block'"
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile"
        Name = "DefaultInboundAction"
        Expected = 1
        Control = "{0} -eq 1"
        Rationale = "Reduce the attack surface of the computer over the network"
    }
    @{
        Category = "Firewall"
        Description = "Ensure 'Domain: Inbound connections' is set to 'Block'"
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile"
        Name = "DefaultInboundAction"
        Expected = 1
        Control = "{0} -eq 1"
        Rationale = "Reduce the attack surface of the computer over the network"
    }
    @{
        Category = "Firewall"
        Description = "Ensure 'Domain: Settings: Display a notification' is set to 'No'"
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile"
        Name = "DisableNotifications"
        Expected = 1
        Control = "{0} -eq 1"
        Rationale = "Avoid complex firewall notifications that could confuse end users"
    }
    @{
        Category = "Firewall"
        Description = "Ensure 'Domain: Logging: Name' is set to '%SystemRoot%\System32\logfiles\firewall\domainfw.log'"
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging"
        Name = "LogFilePath"
        Expected = "%SystemRoot%\System32\logfiles\firewall\domainfw.log"
        Control = "{0} -eq '%SystemRoot%\System32\logfiles\firewall\domainfw.log'"
        Rationale = "Separate each firewall profile (domain, private, public) into its own log file for readability purpose"
    }
    @{
        Category = "Firewall"
        Description = "Ensure 'Domain: Logging: Size limit (KB)' is set to '16,384 KB or greater'"
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging"
        Name = "LogFileSize"
        Expected = 16384
        Control = "{0} -eq 16384"
        Rationale = "Store enough logs to determine the root cause in case of incident"
    }
    @{
        Category = "Firewall"
        Description = "Ensure 'Domain: Logging: Log dropped packets' is set to 'Yes'"
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging"
        Name = "LogDroppedPackets"
        Expected = 1
        Control = "{0} -eq 1"
        Rationale = "Store enough logs to determine the root cause in case of incident"
    }
    @{
        Category = "Firewall"
        Description = "Ensure 'Domain: Logging: Log successful connections' is set to 'Yes'"
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging"
        Name = "LogSuccessfulConnections"
        Expected = 1
        Control = "{0} -eq 1"
        Rationale = "Store enough logs to determine the root cause in case of incident"
    }
    @{
        Category = "Firewall"
        Description = "Ensure 'Private: Firewall state' is set to 'On'"
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile"
        Name = "EnableFirewall"
        Expected = 1
        Control = "{0} -eq 1"
        Rationale = "Reduce the attack surface of the computer over the network"
    }
    @{
        Category = "Firewall"
        Description = "Ensure 'Private: Inbound connections' is set to 'Block'"
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile"
        Name = "DefaultInboundAction"
        Expected = 1
        Control = "{0} -eq 1"
        Rationale = "Reduce the attack surface of the computer over the network"
    }
    @{
        Category = "Firewall"
        Description = "Ensure 'Private: Inbound connections' is set to 'Block'"
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile"
        Name = "DefaultInboundAction"
        Expected = 1
        Control = "{0} -eq 1"
        Rationale = "Reduce the attack surface of the computer over the network"
    }
    @{
        Category = "Firewall"
        Description = "Ensure 'Private: Settings: Display a notification' is set to 'No'"
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile"
        Name = "DisableNotifications"
        Expected = 1
        Control = "{0} -eq 1"
        Rationale = "Avoid complex firewall notifications that could confuse end users"
    }
    @{
        Category = "Firewall"
        Description = "Ensure 'Private: Logging: Name' is set to '%SystemRoot%\System32\logfiles\firewall\privatefw.log'"
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging"
        Name = "LogFilePath"
        Expected = "%SystemRoot%\System32\logfiles\firewall\privatefw.log"
        Control = "{0} -eq '%SystemRoot%\System32\logfiles\firewall\privatefw.log'"
        Rationale = "Separate each firewall profile (domain, private, public) into its own log file for readability purpose"
    }
    @{
        Category = "Firewall"
        Description = "Ensure 'Private: Logging: Size limit (KB)' is set to '16,384 KB or greater'"
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging"
        Name = "LogFileSize"
        Expected = 16384
        Control = "{0} -eq 16384"
        Rationale = "Store enough logs to determine the root cause in case of incident"
    }
    @{
        Category = "Firewall"
        Description = "Ensure 'Private: Logging: Log dropped packets' is set to 'Yes'"
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging"
        Name = "LogDroppedPackets"
        Expected = 1
        Control = "{0} -eq 1"
        Rationale = "Store enough logs to determine the root cause in case of incident"
    }
    @{
        Category = "Firewall"
        Description = "Ensure 'Private: Logging: Log successful connections' is set to 'Yes'"
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging"
        Name = "LogSuccessfulConnections"
        Expected = 1
        Control = "{0} -eq 1"
        Rationale = "Store enough logs to determine the root cause in case of incident"
    }
    @{
        Category = "Firewall"
        Description = "Ensure 'Public: Firewall state' is set to 'On'"
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile"
        Name = "EnableFirewall"
        Expected = 1
        Control = "{0} -eq 1"
        Rationale = "Reduce the attack surface of the computer over the network"
    }
    @{
        Category = "Firewall"
        Description = "Ensure 'Public: Inbound connections' is set to 'Block'"
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile"
        Name = "DefaultInboundAction"
        Expected = 1
        Control = "{0} -eq 1"
        Rationale = "Reduce the attack surface of the computer over the network"
    }
    @{
        Category = "Firewall"
        Description = "Ensure 'Public: Settings: Display a notification' is set to 'No'"
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile"
        Name = "DisableNotifications"
        Expected = 1
        Control = "{0} -eq 1"
        Rationale = "Avoid complex firewall notifications that could confuse end users"
    }
    @{
        Category = "Firewall"
        Description = "Ensure 'Public: Settings: Apply local firewall rules' is set to 'No'"
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile"
        Name = "AllowLocalPolicyMerge"
        Expected = 0
        Control = "{0} -eq 0"
        Rationale = "Avoid special local firewall exceptions that could expose the computer to remote attacks"
    }
    @{
        Category = "Firewall"
        Description = "Ensure 'Public: Settings: Apply local connection security rules' is set to 'No'"
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile"
        Name = "AllowLocalIPsecPolicyMerge"
        Expected = 0
        Control = "{0} -eq 0"
        Rationale = "Avoid special local firewall exceptions that could expose the computer to remote attacks"
    }
    @{
        Category = "Firewall"
        Description = "Ensure 'Public: Logging: Name' is set to '%SystemRoot%\System32\logfiles\firewall\publicfw.log'"
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging"
        Name = "LogFilePath"
        Expected = "%SystemRoot%\System32\logfiles\firewall\publicfw.log"
        Control = "{0} -eq '%SystemRoot%\System32\logfiles\firewall\publicfw.log'"
        Rationale = "Separate each firewall profile (domain, private, public) into its own log file for readability purpose"
    }
    @{
        Category = "Firewall"
        Description = "Ensure 'Public: Logging: Size limit (KB)' is set to '16,384 KB or greater'"
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging"
        Name = "LogFileSize"
        Expected = 16384
        Control = "{0} -eq 16384"
        Rationale = "Store enough logs to determine the root cause in case of incident"
    }
    @{
        Category = "Firewall"
        Description = "Ensure 'Public: Logging: Log dropped packets' is set to 'Yes'"
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging"
        Name = "LogDroppedPackets"
        Expected = 1
        Control = "{0} -eq 1"
        Rationale = "Store enough logs to determine the root cause in case of incident"
    }
    @{
        Category = "Firewall"
        Description = "Ensure 'Public: Logging: Log successful connections' is set to 'Yes'"
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging"
        Name = "LogSuccessfulConnections"
        Expected = 1
        Control = "{0} -eq 1"
        Rationale = "Store enough logs to determine the root cause in case of incident"
    }
    @{
        Category = "MS Security Guide"
        Description = "Ensure 'Enable insecure guest logons' is set to 'Disabled'"
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation"
        Name = "AllowInsecureGuestAuth"
        Expected = 0
        Control = "{0} -eq 0"
        Rationale = "Prevent unauthenticated access to shared folders"
    }
    @{
        Category = "Time Providers"
        Description = "Ensure 'Enable Windows NTP Server' is set to 'Disabled'"
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpServer"
        Name = "Enabled"
        Expected = 0
        Control = "{0} -eq 0"
        Rationale = "Enforce a reliable and accurate account of time needed for many security features"
    }
    @{
        Category = "Time Providers"
        Description = "Ensure 'Enable Windows NTP Client' is set to 'Enabled'"
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpClient"
        Name = "Enabled"
        Expected = 1
        Control = "{0} -eq 1"
        Rationale = "Member servers and workstations should not be time sources for other clients"
    }
    @{
        Category = "Personalization"
        Description = "Ensure 'Prevent enabling lock screen camera' is set to 'Enabled'"
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization"
        Name = "NoLockScreenCamera"
        Expected = 1
        Control = "{0} -eq 1"
        Condition = "Workstation"
        Rationale = "Prevent camera from being invoked on the lock screen"
    }
    @{
        Category = "Personalization"
        Description = "Ensure 'Prevent enabling lock screen slide show' is set to 'Enabled'"
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization"
        Name = "NoLockScreenSlideshow"
        Expected = 1
        Control = "{0} -eq 1"
        Condition = "Workstation"
        Rationale = "Prevent slide show from playing on the lock screen"
    }
    @{
        Category = "Personalization"
        Description = "Ensure 'Allow users to enable online speech recognition services' is set to 'Disabled'"
        Path = "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization"
        Name = "AllowInputPersonalization"
        Expected = 0
        Control = "{0} -eq 0"
        Rationale = "Prevent computer from sending sensitive information to Microsoft"
    }
    @{
        Category = "Personalization"
        Description = "Ensure 'Allow Online Tips' is set to 'Disabled'"
        Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
        Name = "AllowOnlineTips"
        Expected = 0
        Control = "{0} -eq 0"
        Rationale = "Prevent computer from sending sensitive information to Microsoft"
    }
    @{
        Category = "MS Security Guide"
        Description = "Ensure 'Apply UAC restrictions to local accounts on network logons' is set to 'Enabled'"
        Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        Name = "LocalAccountTokenFilterPolicy"
        Expected = 0
        Control = "{0} -eq 0"
        Rationale = "Prevent local accounts from being used for remote administration via network logon"
    }
    @{
        Category = "MS Security Guide"
        Description = "Ensure 'Configure RPC packet level privacy setting for incoming connections' is set to 'Enabled'"
        Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Print"
        Name = "RpcAuthnLevelPrivacyEnabled"
        Expected = 1
        Control = "{0} -eq 1"
        Rationale = "Minimize CVE-2021-1678 exploit likelihood by enforcing authentication level on incoming RPC connections"
    }
    @{
        Category = "MS Security Guide"
        Description = "Ensure 'Configure SMB v1 client driver' is set to 'Enabled: Disable driver'"
        Path = "HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10"
        Name = "Start"
        Expected = 4
        Control = "{0} -eq 4"
        Rationale = "Disable SMBv1 which is a 30 years old protocol much more vulnerable than SMBv2 and SMBv3"
    }
    @{
        Category = "MS Security Guide"
        Description = "Ensure 'Configure SMB v1 server' is set to 'Disabled'"
        Path = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
        Name = "SMB1"
        Expected = 0
        Control = "{0} -eq 0"
        Rationale = "Disable SMBv1 which is a 30 years old protocol much more vulnerable than SMBv2 and SMBv3"
    }
    @{
        Category = "MS Security Guide"
        Description = "Ensure 'Enable Certificate Padding' is set to 'Enabled'"
        Path = "HKLM:\SOFTWARE\Microsoft\Cryptography\Wintrust\Config"
        Name = "EnableCertPaddingCheck"
        Expected = 1
        Control = "{0} -eq 1"
        Rationale = "Minimize CVE-2013-3900 exploit likelihood by configuring WinVerifyTrust function"
    }
    @{
        Category = "MS Security Guide"
        Description = "Ensure 'Enable Structured Exception Handling Overwrite Protection (SEHOP)' is set to 'Enabled'"
        Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel"
        Name = "DisableExceptionChainValidation"
        Expected = 0
        Control = "{0} -eq 0"
        Rationale = "Block exploits that use the Structured Exception Handler (SEH) overwrite technique"
    }
    @{
        Category = "MS Security Guide"
        Description = "Ensure 'LSA Protection' is set to 'Enabled'"
        Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
        Name = "RunAsPPL"
        Expected = 1
        Control = "{0} -eq 1"
        Rationale = "Prevent from reading memory and code injection by non-protected processes on the LSA"
    }
    @{
        Category = "MS Security Guide"
        Description = "Ensure 'NetBT NodeType configuration' is set to 'Enabled: P-node'"
        Path = "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters"
        Name = "NodeType"
        Expected = 2
        Control = "{0} -eq 2"
        Rationale = "Prevent the system from sending NetBIOS broadcasts, which mitigates the risk of NetBIOS Name Service poisoning attacks"
    }
    @{
        Category = "MS Security Guide"
        Description = "Ensure 'WDigest Authentication' is set to 'Disabled'"
        Path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"
        Name = "UseLogonCredential"
        Expected = 0
        Control = "{0} -eq 0"
        Rationale = "Prevent from the plaintext storage of credentials in memory"
    }
    @{
        Category = "Server Message Block"
        Description = "Ensure 'Require Security Signature' is set to 'Enabled'"
        Path = "HKLM:\System\CurrentControlSet\Services\LanManWorkstation\Parameters"
        Name = "RequireSecuritySignature"
        Expected = 1
        Control = "{0} -eq 1"
        Condition = "Workstation"
        Rationale = "Always enforce digital signature for SMB communications"
    }
    @{
        Category = "Server Message Block"
        Description = "Ensure 'Enable Security Signature' is set to 'Enabled'"
        Path = "HKLM:\System\CurrentControlSet\Services\LanManWorkstation\Parameters"
        Name = "EnableSecuritySignature"
        Expected = 1
        Control = "{0} -eq 1"
        Condition = "Workstation"
        Rationale = "If server agrees, enforce digital signature for SMB communications"
    }
    @{
        Category = "Server Message Block"
        Description = "Ensure 'Require Security Signature' is set to 'Enabled'"
        Path = "HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters"
        Name = "RequireSecuritySignature"
        Expected = 1
        Control = "{0} -eq 1"
        Condition = "Server"
        Rationale = "Always enforce digital signature for SMB communications"
    }
    @{
        Category = "Server Message Block"
        Description = "Ensure 'Enable Security Signature' is set to 'Enabled'"
        Path = "HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters"
        Name = "EnableSecuritySignature"
        Expected = 1
        Control = "{0} -eq 1"
        Condition = "Server"
        Rationale = "If client agrees, enforce digital signature for SMB communications"
    }
    @{
        Category = "Network Configuration"
        Description = "Ensure 'MSS: IP source routing protection level' is set to 'Enabled: Highest protection, source routing is completely disabled'"
        Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
        Name = "DisableIPSourceRouting"
        Expected = 2
        Control = "{0} -eq 2"
        Rationale = "Prevent packets from being source routed"
    }
    @{
        Category = "Network Configuration"
        Description = "Ensure 'MSS: Allow ICMP redirects to override OSPF generated routes' is set to 'Disabled'"
        Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
        Name = "EnableICMPRedirect"
        Expected = 0
        Control = "{0} -eq 0"
        Rationale = "Ignore ICMP redirects to limit the system's exposure to attacks that could impact its ability to participate on the network"
    }
    @{
        Category = "Network Configuration"
        Description = "Ensure 'MSS: How often keep-alive packets are sent in milliseconds' is set to 'Enabled: 300,000 or 5 minutes'"
        Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
        Name = "KeepAliveTime"
        Expected = 300000
        Control = "{0} -eq 300000"
        Rationale = "Reduce the risk of a successful DoS attack"
    }
    @{
        Category = "Network Configuration"
        Description = "Ensure 'MSS: Allow IRDP to detect and configure Default Gateway addresses' is set to 'Disabled'"
        Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
        Name = "PerformRouterDiscovery"
        Expected = 0
        Control = "{0} -eq 0"
        Rationale = "Prevent the computer from routing its traffic through another potentially compromised computer"
    }
    @{
        Category = "Network Configuration"
        Description = "Ensure 'MSS: How many times unacknowledged data is retransmitted' is set to 'Enabled: 3'"
        Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
        Name = "TcpMaxDataRetransmissions"
        Expected = 3
        Control = "{0} -eq 3"
        Rationale = "Prevent from denial of service attacks on TCP stack"
    }
)

$SecurityPolicies =
@(
    @{
        Description = "Ensure 'Rename guest account' is configured"
        Category = "Accounts"
        Name = "NewGuestName"
        Expected = "Different from 'Guest'"
        Control = "'{0}' -ne 'Guest'"
        Rationale = "Make more difficult to guess guest username and password combination"
    }
    @{
        Description = "Ensure 'Rename administrator account' is configured"
        Category = "Accounts"
        Name = "NewAdministratorName"
        Expected = "Different from 'Administrator'"
        Control = "'{0}' -ne 'Administrator'"
        Rationale = "Make more difficult to guess administrator username and password combination"
    }
    @{
        Description = "Ensure 'Guest account status' is set to 'Disabled'"
        Category = "Accounts"
        Name = "EnableGuestAccount"
        Expected = 0
        Control = "{0} -eq 0"
        Rationale = "Prevent unauthorized use of default guest account"
    }
    @{
        Description = "Ensure 'Reset account lockout counter after' is set to '15 or more minute(s)'"
        Category = "Account Lockout Policy"
        Name = "ResetLockoutCount"
        Expected = "15 or more"
        Control = "{0} -ge 15"
        Rationale = "Reduce the chance of accidental lockouts from users"
    }
    @{
        Description = "Ensure 'Allow Administrator account lockout' is set to 'Enabled'"
        Category = "Account Lockout Policy"
        Name = "AllowAdministratorLockout"
        Expected = 1
        Control = "{0} -eq 1"
        Rationale = "Reduce the likelihood of a successful brute-force attack on administrator account"
    }
    @{
        Description = "Ensure 'Account lockout threshold' is set to '5 or fewer invalid logon attempt(s), but not 0'"
        Category = "Account Lockout Policy"
        Name = "LockoutBadCount"
        Expected = "5 or less, but not 0"
        Control = "{0} -gt 0 -and {0} -le 5"
        Rationale = "Reduce the likelihood of a successful brute-force attack"
    }
    @{
        Description = "Ensure 'Account lockout duration' is set to '0' or '15 or more minute(s)'"
        Category = "Account Lockout Policy"
        Name = "LockoutDuration"
        Expected = "0 or more than 15"
        Control = "{0} -eq 0 -or {0} -ge 15"
        Rationale = "Reduce the likelihood of a successful brute-force attack"
    }
    @{
        Description = "Ensure 'Enforce password history' is set to '24 or more password(s)'"
        Category = "Password Policy"
        Name = "PasswordHistorySize"
        Expected = "24 or more"
        Control = "{0} -ge 24"
        Rationale = "Prevent potentially compromised credentials of being exploitable"
    }
    @{
        Description = "Ensure 'Maximum password age' is set to '365 or fewer days, but not 0'"
        Category = "Password Policy"
        Name = "MaximumPasswordAge"
        Expected = "365 or less, but not 0"
        Control = "{0} -gt 0 -and {0} -le 365"
        Rationale = "Reduce the likelihood of a successful brute-force attack"
    }
    @{
        Description = "Ensure 'Minimum password age' is set to '1 or more day(s)'"
        Category = "Password Policy"
        Name = "MinimumPasswordAge"
        Expected = "1 or more"
        Control = "{0} -ge 1"
        Rationale = "Make more difficult to bypass the 'Enforce password history' policy"
    }
    @{
        Description = "Ensure 'Minimum password length' is set to '14 or more character(s)'"
        Category = "Password Policy"
        Name = "MinimumPasswordLength"
        Expected = "14 or more"
        Control = "{0} -ge 14"
        Rationale = "Increase passwords complexity to reduce the likelihood of a successful brute-force attack"
    }
    @{
        Description = "Ensure 'Password must meet complexity requirements' is set to 'Enabled'"
        Category = "Password Policy"
        Name = "PasswordComplexity"
        Expected = 1
        Control = "{0} -eq 1"
        Rationale = "Increase passwords complexity to reduce the likelihood of a successful brute-force attack"
    }
)

New-Variable -Name AuditPolicies -Value $AuditPolicies -Scope Script -Force
New-Variable -Name RegistryEntries -Value $RegistryEntries -Scope Script -Force
New-Variable -Name SecurityPolicies -Value $SecurityPolicies -Scope Script -Force