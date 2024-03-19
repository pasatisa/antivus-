# Define the variables used in the script
$Version = "2.37"
$HKEY_LOCAL_MACHINE = 0x80000002
$strComputer = "."
$wbemCimtypeString = 8
$wbemCimtypeUint32 = 19
$wbemCimtypeBoolean = 11
$wbemFlagReturnImmediately = 0x10
$wbemFlagForwardOnly = 0x20
$OutOfDateDays = 5
$InstallLocation = $env:AllUsersProfile
$CurrentDate = Get-Date
$S1HelperObj = New-Object -ComObject "winmgmts:{impersonationLevel=impersonate}!\\$strComputer\root\default:StdRegProv"
$S1AgentStatus = "SecurityCenter"
$S1AgentStatus2 = "SecurityCenter2"
$WshShell = New-Object -ComObject "WScript.Shell"
$output = [Console]::Out
$RegEx = [Regex]::new('"', 'AntiVirusProduct')
$ParentWMINamespace = Get-WmiObject -Class "__NAMESPACE" -Namespace "root" -ComputerName $strComputer | Where-Object { $_.Name -eq "SecurityCenter2" }
$OutOfDateDays = 5
$CurrentDate = Get-Date
$HTTP_Request = [System.Net.WebRequest]::Create("https://www.google.com")
$HTTP_Response = $HTTP_Request.GetResponse()
$HTTP_Status = [int]$HTTP_Response.StatusCode

if ($HTTP_Status -eq 200) {
    $StatusCode = "Online"
} else {
    $StatusCode = "Offline"
}

$HTTP_Response.Close()

# Let's see if the user specified whether or not the script should enter data into WMI if no A/V is found.
if ($args.Count -eq 1) {
    $NoAVBehavior = $args[0]
    if ($NoAVBehavior -eq "WRITE") {
        Write-Output "- The $NoAVBehavior flag has been specified as a command-line parameter."
    }
    elseif ($NoAVBehavior -eq "DONOTWRITE") {
        Write-Output "- The $NoAVBehavior flag has been specified as a command-line parameter."
    }
    else {
        Write-Output "- An invalid command-line parameter has been specified. Please specify either WRITE or DONOTWRITE, or do not specify a command-line parameter at all."
        exit 0
    }
}
else {
    # Write-Output "- The command-line parameter (either WRITE or DONOTWRITE) for choosing whether or not to write data to WMI if an A/V product isn't found was not specified. This script will write data to WMI regardless of whether or not an A/V product is discovered."
}

# This is the meat of the script - where all of the functions are called.
Write-Output "- This is version $Version of the script."

# Call functions to determine OS type and version
OSType
OSVersion

# Call function to detect installed AV software
DetectInstalledAV

Write-Output "- $InstalledAV has been detected."

# Check installed AV and call respective functions
if ($InstalledAV -eq "Trend Micro Apex One" -or $InstalledAV -eq "Trend Micro Worry-Free Business Security 6" -or $InstalledAV -eq "WFBSS" -or $InstalledAV -eq "Trend Micro WFBSS" -or $InstalledAV -eq "Trend Micro Worry-Free Business Security" -or $InstalledAV -eq "Trend Micro OfficeScan" -or $InstalledAV -eq "Trend Micro Worry-Free Business Security Services" -or $InstalledAV -eq "Trend Micro WFBSH_Agent") {
    ObtainTrendMicroData
}
elseif ($InstalledAV -eq "Trend Micro Worry-Free Business Security 7") {
    ObtainTrend7AVData
}
elseif ($InstalledAV -eq "Symantec Endpoint Protection") {
    ObtainSymantecESData
}
elseif ($InstalledAV -eq "Symantec AntiVirus") {
    ObtainSymantecAVData
}
elseif ($InstalledAV -eq "Sophos Anti-Virus" -or $InstalledAV -eq "Sophos Endpoint Protection" -or $InstalledAV -eq "Sophos Anti-Virus 10") {
    # If the script is launched on a 64-bit machine, re-launch it in the 32-bit command prompt to properly detect Sophos
    # Skipping this step in PowerShell as it's not necessary
    ObtainSophos10AVData
}

}
elseif ($InstalledAV -eq "Kaspersky Anti-Virus 2012") {
    ObtainKaspersky2012AVData
}
elseif ($InstalledAV -eq "Kaspersky Anti-Virus 6.0") {
    ObtainKaspersky60AVData
}
elseif ($InstalledAV -eq "Microsoft System Center Endpoint Protection" -or $InstalledAV -eq "Microsoft Security Essentials" -or $InstalledAV -eq "Microsoft Forefront" -or $InstalledAV -eq "Microsoft System Center Endpoint Protection (Managed Defender)") {
    ObtainSecurityEssentialsAVData
}
# Add other elseif blocks for each installed AV software and call respective functions
else {
    Write-Output "Unknown or unsupported AV software detected: $InstalledAV"
}


# Check to see if an instance of the WMI namespace exists
$WMINamespaceExistance = WMINamespaceExistanceCheck $strWMINamespace

if ($WMINamespaceExistance -eq "1") {
    # The namespace already exists
    # output.writeline "- The Namespace already exists."
    
    # Check if the WMI class exists
    $WMIClassExists = WMIClassExists $strWMINamespace $strComputer $strWMIClassWithQuotes
    
    if ($WMIClassExists) {
        # The WMI Class exists; let's delete it so that we don't have any duplicate data laying around in WMI.
        # output.writeline "- The WMI Class exists; let's delete it so that we don't have any duplicate data laying around in WMI."
        Remove-WmiObject -Namespace $strWMINamespace -Class $strWMIClassNoQuotes -ComputerName $strComputer
        CreateWMIClass
        PopulateWMIClass
    }
    else {
        # The Namespace exists, but the WMI class does not.
        # output.writeline "- The Namespace exists, but the WMI class does not. Curious." 
        CreateWMIClass
        PopulateWMIClass
    }
}
else {
    # Create the WMI Namespace (if it doesn't already exist), the WMI Class, and populate the class with data. 
    # output.writeline "- The WMI Namespace and Class do not exist"
    CreateWMINamespace
    CreateWMIClass
    PopulateWMIClass
}
# Sub-rotina: OSType
Function OSType {
    # Determinar se esta é uma máquina de 32 bits ou de 64 bits (isso determinará quais valores de registro modificamos)
    $objWMIService = Get-WmiObject -Class Win32_Processor -Filter "DeviceID='CPU0'"
    $AddressWidth = $objWMIService.AddressWidth

    $Registry32 = "SOFTWARE\"
    $Registry64 = "SOFTWARE\Wow6432Node\"
    
    if ($AddressWidth -eq 64) {
        # Esta é uma máquina de 64 bits
        $Registry = $Registry64
        $ProgramFiles = [System.Environment]::ExpandEnvironmentVariables("%PROGRAMFILES(x86)%")
        $ProgramFiles64 = [System.Environment]::ExpandEnvironmentVariables("%PROGRAMW6432%")
        Write-Output "- Esta é uma máquina de 64 bits."
    }
    elseif ($AddressWidth -eq 32) {
        # Esta é uma máquina de 32 bits
        $Registry = $Registry32
        $ProgramFiles = [System.Environment]::ExpandEnvironmentVariables("%PROGRAMFILES%")
        Write-Output "- Esta é uma máquina de 32 bits."
    }
    else {
        # O Windows não sabe qual tipo de SO está sendo executado
        Write-Output "- O tipo de SO é desconhecido - o script não pode detectar se é 32 bits ou 64 bits."
    }

    # Vamos pegar o valor %ProgramData%, pois será usado para detectar o produto AV instalado
    $ProgramData = [System.Environment]::ExpandEnvironmentVariables("%PROGRAMDATA%")
}

# Sub-rotina: DetectInstalledAV
Function DetectInstalledAV {
    # $InstalledAV é uma variável que precisa ser definida anteriormente, não está clara de onde ela vem no seu script
    Write-Output $InstalledAV

    # Definição dos caminhos de registro para diferentes produtos AV
    $strMcAfeePath = $Registry + "McAfee\AVEngine\DAT"
    $strTrendKeyPath = $Registry + "TrendMicro\PC-cillinNTCorp\CurrentVersion\Misc.\"
    $strTrend7KeyPath = "SOFTWARE\TrendMicro\UniClient\1600\Update\PatternOutOfDateDays"
    $strSymantecESKeyPath = $Registry + "Symantec\Symantec Endpoint Protection\AV\"
    # Definir outros caminhos de registro conforme necessário...
}

# Check if N-able's Endpoint Security is installed
# We need to check different registry values depending on the OS

# Registry paths for different versions of N-able's Endpoint Security
$strEndpointSecurityKeyPaths = @(
    $Registry + "Microsoft\Windows\CurrentVersion\Uninstall\AVTC64",
    $Registry + "Microsoft\Windows\CurrentVersion\Uninstall\AVNT64",
    $Registry + "Microsoft\Windows\CurrentVersion\Uninstall\AVTC",
    $Registry + "Microsoft\Windows\CurrentVersion\Uninstall\AVNT"
)



# Check to see what A/V product is installed

# Check for Trend Micro OfficeScan
if (Test-Path "HKLM:\$strTrendKeyPath\ProductVer") {
    $InstalledAV = "Trend Micro OfficeScan"
}





# Check for VIPRE AntiVirus
elseif (Test-Path "HKLM:\$strVIPREAVKeyPath\ProductCode") {
    $InstalledAV = "VIPRE AntiVirus"
}


# Check for Kaspersky Anti-Virus 2012
elseif (Test-Path "HKLM:\$strKasperskyAV2012KeyPath\SettingsVersion") {
    $InstalledAV = "Kaspersky Anti-Virus 2012"
}

# Check for Kaspersky Anti-Virus 6.0
elseif (Test-Path "HKLM:\$strKasperskyAV60KeyPath\SettingsVersion") {
    $InstalledAV = "Kaspersky Anti-Virus 6.0"
}

# Check for Kaspersky Endpoint Security 8
elseif (Test-Path "HKLM:\$strKasperskyKES8KeyPath\SettingsVersion") {
    $InstalledAV = "Kaspersky Endpoint Security 8"
}


}

# Check for SentinelOne
elseif (Test-Path "$ProgramFiles64\SentinelOne") {
    $InstalledAV = "SentinelOne"
}

# If no specific AV product is detected, set InstalledAV to "Unknown"
else {
    $InstalledAV = "Unknown"
}

# Check for Webroot SecureAnywhere
if (Test-Path "HKLM:\$strWebRootStatusPath\Version") {
    $InstalledAV = "Webroot SecureAnywhere"
}


# Check for Avast! (64-bit)
elseif (Test-Path "HKLM:\$strAvastRegPath64\Version") {
    $InstalledAV = "Avast!"
    $strAvastInstallPath = (Get-ItemProperty -Path "HKLM:\$strAvastRegPath64" -Name "ProgramFolder").ProgramFolder
}

# Parece que as versões mais recentes do Endpoint Cloud não mais registram no Wow6432Node em máquinas de 64 bits. Este trecho de código lidará com esse cenário.
if ($FoundGUID -eq $false) {
    $arrSubKeys = $null
    $oReg.EnumKey([Microsoft.Win32.RegistryHive]::LocalMachine, "SOFTWARE\NORTON\", [ref]$arrSubKeys)
    foreach ($subkey in $arrSubKeys) {
        # Endpoint Cloud armazena as informações que estamos procurando em uma subchave com o título de GUID. Vamos descobrir esse GUID.
        if (Test-Path "HKLM:\SOFTWARE\NORTON\$subkey\PRODUCTVERSION") {
            $strSEPCloudRegPath2 = "$strSEPCloudRegPath0$subkey"
            break
        }
    }
}
else {
    Write-Output "- Não foi possível encontrar mais detalhes sobre o Symantec Endpoint Protection Cloud no registro. Talvez tenha sido desinstalado?"
    exit
}



#--- Verificar o Sophos para Ambientes Virtuais ---
elseif (Test-Path "HKLM:\$strSophosVirtualAVKeyPath\SGVM Deployment Service\InstalledPath") {
    $InstalledAV = "Sophos for Virtual Environments"
}
#--- Verificar o Carbon Black, também conhecido como "Cb Defense Sensor 64-bit" ---
elseif (Get-Service "CbDefense" -ErrorAction SilentlyContinue) {
    # Se o serviço estiver em execução, o Carbon Black está instalado
    $InstalledAV = "Carbon Black"
}

#--- Verificar o Microsoft System Center Endpoint Protection ---
elseif (Test-Path "HKLM:\$strSecurityEssentialsKeyPath\LastSuccessfullyAppliedPolicy") {
    $InstalledAV = "Microsoft System Center Endpoint Protection"
}
#--- Verificar o Cisco AMP ---
elseif (Test-Path "$ProgramFiles64\Cisco\AMP\local.xml") {
    $InstalledAV = "Cisco Advanced Malware Protection (AMP)"
}
#--- Verificar a Edição Corporativa do Malwarebytes' ---
elseif (Test-Path "HKLM:\$strMalwareBytesRegPath64\InstallPath") {
    $InstalledAV = "Malwarebytes' Corporate Edition"
}


#--- Função: Obter Dados do Trend Micro ---
function ObterDadosTrendMicro {
    # Obter a versão do produto do registro
    $strTrendProductVersion = "Registry\TrendMicro\PC-cillinNTCorp\CurrentVersion\Misc.\TmListen_Ver"
    $strTrendRealTimeKeyPath = "Registry\TrendMicro\PC-cillinNTCorp\CurrentVersion\Real Time Scan Configuration\"
    $strTrendKeyPath = "Registry\TrendMicro\PC-cillinNTCorp\CurrentVersion\"

    $InputRegistryKey1 = "InternalPatternVer"
    $InputRegistryKey2 = "PatternDate"
    $InputRegistryKey3 = "InternalNonCrcPatternVer"
    $InputRegistryKey4 = "Enable"
    $InputRegistryKey5 = "NonCrcPatternDate"
    $InputRegistryKey6 = "LastUpdate"
    $InputRegistryKey7 = "TmListen_Ver"

    $ReturneddwValue3 = Get-ItemPropertyValue -Path $strTrendRealTimeKeyPath -Name $InputRegistryKey4
    $ReturneddwValue1 = Get-ItemPropertyValue -Path $strTrendKeyPath -Name $InputRegistryKey1
    $ReturneddwValue2 = Get-ItemPropertyValue -Path $strTrendKeyPath -Name $InputRegistryKey3
    $ProductVersion = Get-ItemPropertyValue -Path $strTrendProductVersion

    $OnAccessScanningEnabled = if ($ReturneddwValue3 -eq 1) { $true } elseif ($ReturneddwValue3 -eq 0) { $false } else { $false }

    Write-Output "- Is Real Time Scanning Enabled? $OnAccessScanningEnabled"

    $ReturneddwValue4 = Get-ItemPropertyValue -Path "Registry\TrendMicro\PC-cillinNTCorp\CurrentVersion\iCRC Scan\" -Name "scantype"
    if ($ReturneddwValue4 -eq 1) {
        $RawAVVersion = $ReturneddwValue2
        Write-Output "- Smart Scan is enabled, so we'll use the InternalNonCrcPatternVer registry value."
    } else {
        Write-Output "- Smart Scan must not be installed. Using the InternalPatternVer registry key."
        $RawAVVersion = $ReturneddwValue1
    }

    # Convertendo o valor hexadecimal para decimal
    $FormattedAVVersion = ""
    switch ($RawAVVersion.Length) {
        6 { $FormattedAVVersion = "{0}.{1}.{2}" -f $RawAVVersion[0], $RawAVVersion.Substring(1,3), $RawAVVersion.Substring(4,2) }
        7 { $FormattedAVVersion = "{0}.{1}.{2}" -f $RawAVVersion.Substring(0,2), $RawAVVersion.Substring(2,3), $RawAVVersion.Substring(5,2) }
        default { $FormattedAVVersion = "No Version" }
    }

    Write-Output $FormattedAVVersion
}


# Formate a Idade do Padrão que estava no registro para torná-la mais legível
function FormatarIdadePadrao {
    param(
        [string]$InstalledAV,
        [string]$InputRegistryKey2,
        [string]$InputRegistryKey6,
        [string]$strTrendKeyPath
    )

    if ($InstalledAV -like "*OfficeScan*") {
        $ReturnedstrValue1 = Get-ItemPropertyValue -Path $strTrendKeyPath -Name $InputRegistryKey2
        $FormattedPatternAge = "{0}/{1}/{2}" -f $ReturnedstrValue1.Substring(0,4), $ReturnedstrValue1.Substring(4,2), $ReturnedstrValue1.Substring(6,2)
    } else {
        $ReturnedstrValue1 = Get-ItemPropertyValue -Path "Registry\TrendMicro\PC-cillinNTCorp\CurrentVersion\UpdateInfo\" -Name $InputRegistryKey6
        $FormattedPatternAge = [datetime]::FromFileTime($ReturnedstrValue1)
    }

    # Calcular quanto tempo realmente tem o padrão A/V
    $CalculatedPatternAge = (Get-Date) - $FormattedPatternAge

    Write-Output "- The A/V product version is: $FormattedAVVersion"
    Write-Output "- The date of the A/V Definition File is: $FormattedPatternAge"
    Write-Output "- The A/V Definition File is $($CalculatedPatternAge.Days) days old."

    CalcularIdadeAV
}

# Function: ObtainSymantecESData
function ObterDadosSymantecES {
    #Grab the Symantec data from the Registry
    $strSymantecESKeyPath = "Registry\Symantec\Symantec Endpoint Protection"
    $InputRegistryKey1 = "PatternFileDate"
    $InputRegistryKey2 = "ScanEngineVersion"
    $InputRegistryKey3 = "OnOff"
    $InputRegistryKey4 = "PatternFileRevision"
    $InputRegistryKey5 = "PRODUCTVERSION"
    $InputRegistryKey6 = "PRODUCTNAME"

    $ReturnedBinaryArray1 = Get-ItemPropertyValue -Path "Registry\Symantec\Symantec Endpoint Protection\AV" -Name $InputRegistryKey1
    $RawAVVersion = Get-ItemPropertyValue -Path "Registry\Symantec\Symantec Endpoint Protection\AV" -Name $InputRegistryKey2
    $RawOnAccessScanningEnabled = Get-ItemPropertyValue -Path "Registry\Symantec\Symantec Endpoint Protection\AV\Storages\FileSystem\RealTimeScan" -Name $InputRegistryKey3
    $Revision = Get-ItemPropertyValue -Path "Registry\Symantec\Symantec Endpoint Protection\AV" -Name $InputRegistryKey4

    # If it's Symantec ES 12, the ProductVersion value is stored in one location. If it's Symantec ES 11, it's stored in a different location.
    # Let's check to see if it's in the location for ES 12 first.
    if (Test-Path "Registry\Symantec\Symantec Endpoint Protection\CurrentVersion\PRODUCTVERSION") { # It's version 12 or newer!
        $ProductVersion = Get-ItemPropertyValue -Path "Registry\Symantec\Symantec Endpoint Protection\CurrentVersion" -Name $InputRegistryKey5
        $ProductName = Get-ItemPropertyValue -Path "Registry\Symantec\Symantec Endpoint Protection\CurrentVersion" -Name $InputRegistryKey6
    } else {
        $ProductVersion = Get-ItemPropertyValue -Path "Registry\Symantec\Symantec Endpoint Protection\SMC" -Name $InputRegistryKey5
        $ProductName = "Symantec Endpoint Protection"
    }

    # Set the right 'InstalledAV' value (it should include the product name and version)
    $InstalledAV = "$ProductName $ProductVersion"

    # Let's figure out if Real Time Scanning is enabled or not
    if ($RawOnAccessScanningEnabled -eq 0) {
        $OnAccessScanningEnabled = $false
    } elseif ($RawOnAccessScanningEnabled -eq 1) {
        $OnAccessScanningEnabled = $true
    }

    # Output the obtained Symantec data
    Write-Output "Installed A/V: $InstalledAV"
    Write-Output "Is Real Time Scanning Enabled? $OnAccessScanningEnabled"
}

# The A/V Definition File Date is a binary value - let's format things appropriately.
$SymantecAVYear = $ReturnedBinaryArray1[0] + 1970  # Need to add 1970 to the value seen in the registry

# Need to convert the month from its decimal value to a human-readable value
$SymantecAVMonth = $ReturnedBinaryArray1[1]
if ($SymantecAvMonth -eq "0") {
    $SymantecAvMonth = "01"
} elseif ($SymantecAvMonth -eq "1") {
    $SymantecAvMonth = "02"
} elseif ($SymantecAvMonth -eq "2") {
    $SymantecAvMonth = "03"
} elseif ($SymantecAvMonth -eq "3") {
    $SymantecAvMonth = "04"
} elseif ($SymantecAvMonth -eq "4") {
    $SymantecAvMonth = "05"
} elseif ($SymantecAvMonth -eq "5") {
    $SymantecAvMonth = "06"
} elseif ($SymantecAvMonth -eq "6") {
    $SymantecAvMonth = "07"
} elseif ($SymantecAvMonth -eq "7") {
    $SymantecAvMonth = "08"
} elseif ($SymantecAvMonth -eq "8") {
    $SymantecAvMonth = "09"
} elseif ($SymantecAvMonth -eq "9") {
    $SymantecAvMonth = "10"
} elseif ($SymantecAvMonth -eq "10") {
    $SymantecAvMonth = "11"
} elseif ($SymantecAvMonth -eq "11") {
    $SymantecAvMonth = "12"
}

$SymantecAVDate = $ReturnedBinaryArray1[2]

# Let's add a zero in front of the date value if it's less than 10. We like pretty things.
if ($SymantecAvDate -lt 10) {
    $SymantecAvDate = "0$SymantecAvDate"
}

$FormattedPatternAge = "$SymantecAVYear/$SymantecAVMonth/$SymantecAVDate"
Write-Output "- The formatted date of the A/V Definition File is: $FormattedPatternAge"

$FormattedAVVersion = "$FormattedPatternAge r$Revision"
Write-Output "- The formatted A/V Version is: $FormattedAVVersion"

# Calculate how old the A/V Pattern really is
$CalculatedPatternAge = New-TimeSpan -Start $FormattedPatternAge -End $CurrentDate
Write-Output "- The A/V Definition File is $($CalculatedPatternAge.Days) days old."

CalculateAVAge  # Call the function to determine how old the A/V Definitions are


# Sub: CreateWMINamespace
# *****************************

function CreateWMINamespace {
    Write-Output "- Creating the WMI namespace"
    $objItem = $ParentWMINamespace.Get("__Namespace")
    $objNewNamespace = $objItem.SpawnInstance_()
    $objNewNamespace.Name = $strWMINamespace
    $objNewNamespace.Put_()
}

# Function: WMIClassExists
# Thanks to http://gallery.technet.microsoft.com/ScriptCenter/en-us/a1b23364-34cb-4b2c-9629-0770c1d22ff0 for this code
# *****************************
function Test-WMIClassExists {
    param(
        [string]$strWMINamespace,
        [string]$strComputer,
        [string]$strWMIClassWithQuotes
    )

    $WMIClassExists = $false
    $WMINamespace = Get-WmiObject -Namespace "root\$strWMINamespace" -ComputerName $strComputer
    $colClasses = $WMINamespace.SubclassesOf()

    foreach ($objClass in $colClasses) {
        if ($objClass.Path.Path -like "*$strWMIClassWithQuotes*") {
            $WMIClassExists = $true
            break
        }
    }

    $WMIClassExists
}


    # Debug code, if needed
    # Write-Output "- Version Number: $FormattedAVVersion"
    # Write-Output "- Installed AV: $InstalledAV"
    # Write-Output "- On-Access Scanning: $OnAccessScanningEnabled"
    # Write-Output "- Product Up-to-Date: $ProductUpToDate"

    # Create an instance of the WMI class using SpawnInstance_
    $WMINamespace = Get-WmiObject -Namespace "root\$strWMINamespace" -ComputerName $strComputer
    $objGetClass = $WMINamespace.Get($strWMIClassNoQuotes)
    $objNewInstance = $objGetClass.SpawnInstance_()
    $objNewInstance.VersionNumber = $FormattedAVVersion
    $objNewInstance.displayName = $InstalledAV
    $objNewInstance.onAccessScanningEnabled = $OnAccessScanningEnabled
    $objNewInstance.ProductUpToDate = $ProductUpToDate
    $objNewInstance.ScriptExecutionTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Output "- Populating the WMI Class with the data."

    # Write the instance into the WMI repository
    $objNewInstance.Put()
}

# *****************************  
# Function: RegKeyExists
# Retorna um valor (true / false)
# Agradecimentos a http://www.tek-tips.com/faqs.cfm?fid=5864 por este código
# ************************************
function RegKeyExists ($RegistryKey) {

    # Se não houver a chave ao ler, retornará um erro, então precisamos continuar
    $ErrorActionPreference = "SilentlyContinue"

    # Tente ler a chave
    $null = Get-ItemProperty -Path $RegistryKey

    # Restaure as configurações de ação de erro
    $ErrorActionPreference = "Continue"

    # Verifique se ocorreu um erro
    if (-not $?) {
        return $false
    } else {
        return $true
    }
}


# *************************************  
# Sub: ObtainKaspersky2012AVData
# *************************************
function ObtainKaspersky2012AVData {
    $strKaspersky2012AVDatePath = $Registry + "KasperskyLab\protected\AVP12\"
    $AVDatVersion = (Get-ItemPropertyValue -Path "${strKasperskyAVDatePath}Data\" -Name "LastSuccessfulUpdate")

    # O valor AVDatVersion é um timestamp UNIX - então este script precisa convertê-lo para um formato legível antes de continuar.
    $FormattedPatternAge = [datetime]::FromFileTime($AVDatVersion)
    $CalculatedPatternAge = (Get-Date) - $FormattedPatternAge
    Write-Output "- A última vez que o Kaspersky foi atualizado foi há $CalculatedPatternAge dias."
     
    CalculateAVAge # Chame a função para determinar a idade das definições de A/V

    # Vamos descobrir se a verificação em tempo real está ativada ou não
    # NOTA: Neste ponto, não consigo descobrir isso - nenhum valor de registro parece mudar quando você habilita/desabilita esse recurso no Kaspersky.
    $RawOnAccessScanningEnabled = (Get-ItemPropertyValue -Path "${strKasperskyAVDatePath}settings\def\" -Name "EnableSelfProtection")
    if ($RawOnAccessScanningEnabled -eq 0) {
        $OnAccessScanningEnabled = $false
    } elseif ($RawOnAccessScanningEnabled -eq 1) {
        $OnAccessScanningEnabled = $true
    }

    Write-Output "- A verificação em tempo real está habilitada? $OnAccessScanningEnabled"
  
    # Vamos descobrir o número da versão
    $FormattedAVVersion = (Get-ItemPropertyValue -Path "${strKaspersky2012AVDatePath}settings\def\" -Name "SettingsVersion")
    Write-Output "- A versão do Kaspersky em execução é: $FormattedAVVersion"
}

# *************************************  
# Sub: ObtainKaspersky60AVData
# *************************************
function ObtainKaspersky60AVData {
    $strKasperskyAV60DatePath = $Registry + "KasperskyLab\protected\AVP80\"
    $AVDatVersion = (Get-ItemPropertyValue -Path "${strKasperskyAV60DatePath}Data\" -Name "LastSuccessfulUpdate")

    # O valor AVDatVersion é um timestamp UNIX - então este script precisa convertê-lo para um formato legível antes de continuar.
    $FormattedPatternAge = [datetime]::FromFileTime($AVDatVersion)
    $CalculatedPatternAge = (Get-Date) - $FormattedPatternAge
    Write-Output "- A última vez que o Kaspersky foi atualizado foi há $CalculatedPatternAge dias."
     
    CalculateAVAge # Chame a função para determinar a idade das definições de A/V

    # Vamos descobrir se a verificação em tempo real está ativada ou não
    # NOTA: Neste ponto, não consigo descobrir isso - nenhum valor de registro parece mudar quando você habilita/desabilita esse recurso no Kaspersky.
    $RawOnAccessScanningEnabled = (Get-ItemPropertyValue -Path "${strKasperskyAV60DatePath}settings\def\" -Name "EnableSelfProtection")
    if ($RawOnAccessScanningEnabled -eq 0) {
        $OnAccessScanningEnabled = $false
    } elseif ($RawOnAccessScanningEnabled -eq 1) {
        $OnAccessScanningEnabled = $true
    }

    Write-Output "- A verificação em tempo real está habilitada? $OnAccessScanningEnabled"
  
    # Vamos descobrir o número da versão
    $FormattedAVVersion = (Get-ItemPropertyValue -Path "${strKasperskyAV60DatePath}settings\" -Name "SettingsVersion")
    Write-Output "- A versão do Kaspersky em execução é: $FormattedAVVersion"
}


# *************************************  
# Sub: ObtainSecurityEssentialsAVData
# *************************************
function ObtainSecurityEssentialsAVData {
    # Em testes, foi descoberto que o Microsoft Security Essentials (ou MS Forefront) *sempre* escreve neste caminho - ele não muda se a máquina for 32 bits ou 64 bits.
    # Portanto, para lidar com esse cenário, este script usará apenas um caminho - que é diferente de todas as outras aplicações de A/V.
    if ($InstalledAV -eq "Microsoft Forefront") {
        $strSecurityEssentialsKeyPath = "Software\Microsoft\Microsoft Forefront\Client Security\1.0\AM\"
    } else {
        if (RegKeyExists("HKLM\Software\Microsoft\Microsoft Antimalware\Signature Updates\AVSignatureVersion")) {
            $strSecurityEssentialsKeyPath = "Software\Microsoft\Microsoft Antimalware\"
        } else {
            $strSecurityEssentialsKeyPath = "Software\Microsoft\Windows Defender\"
        }
    }
    
    # Vamos pegar a versão da definição A/V que o Security Essentials está usando
    $FormattedAVVersion = (Get-ItemPropertyValue -Path "${strSecurityEssentialsKeyPath}Signature Updates\" -Name "AVSignatureVersion")
    Write-Output "- A versão do A/V que o $InstalledAV está executando é: $FormattedAVVersion"
    
    # Vamos descobrir se a Verificação em Tempo Real está habilitada ou não
    if (RegKeyExists("HKLM\$strSecurityEssentialsKeyPath\Real-Time Protection\DisableRealtimeMonitoring")) {
        Write-Output "- O valor de registro DisableRealTimeMonitoring existe, então vamos verificar e ver como ele foi configurado."
        $RawOnAccessScanningEnabled = (Get-ItemPropertyValue -Path "${strSecurityEssentialsKeyPath}Real-Time Protection\" -Name "DisableRealTimeMonitoring")
        if ($RawOnAccessScanningEnabled -eq 1) {
            $OnAccessScanningEnabled = $false
        } else {
            $OnAccessScanningEnabled = $true
        }
    } else {
        $OnAccessScanningEnabled = $true
    }
    
    Write-Output "- A Verificação em Tempo Real está habilitada? $OnAccessScanningEnabled"
    
    # Vamos pegar a data da última atualização das definições de A/V. Como ela é armazenada como um valor REG_BINARY, precisaremos convertê-la.
    $RawAVDefDate = (Get-ItemPropertyValue -Path "${strSecurityEssentialsKeyPath}Signature Updates\" -Name "AVSignatureApplied")
    $dtmDate = [datetime]::FromFileTime(([BitConverter]::ToInt64($RawAVDefDate, 0)))
    Write-Output "- A data convertida é: $dtmDate"
    
    # - VERSÃO 1.71 - alterando a formatação da data para corrigir problema regional
    $CurrentDate = Get-Date -Format "yyyy/MM/dd"
    $CalculatedPatternAge = ($CurrentDate - $dtmDate).Days
    Write-Output "- A última vez que $InstalledAV foi atualizado foi há $CalculatedPatternAge dias."
    
    CalculateAVAge # Chame a função para determinar a idade das definições de A/V
}

# *************************************  
# Sub: ObtainKES8Data
# *************************************
function ObtainKES8Data {
    $strKasperskyKES8AVDatePath = "Registry\KasperskyLab\protected\KES8\"
    $AVDatVersion = (Get-ItemPropertyValue -Path "${strKasperskyKES8AVDatePath}Data\" -Name "LastSuccessfulUpdate")
    
    # O valor AVDatVersion é um timestamp UNIX - então este script precisa convertê-lo para um formato legível antes de continuar.
    $FormattedPatternAge = [datetime]::FromFileTime($AVDatVersion)
    $CalculatedPatternAge = (Get-Date).Subtract($FormattedPatternAge).Days
    Write-Output "- A última vez que o Kasperky foi atualizado foi há $CalculatedPatternAge dias."
    
    CalculateAVAge # Chame a função para determinar a idade das definições de A/V
    
    $oShell = New-Object -ComObject "WScript.Shell"
    $oExec = $oShell.Exec("${env:ProgramFiles}\Kaspersky Lab\Kaspersky Endpoint Security 8 for Windows\avp.com status FM")
    $sLine = $oExec.StdOut.ReadLine()
    if ($sLine -match "running") {
        $OnAccessScanningEnabled = $true
    } else {
        $OnAccessScanningEnabled = $false
    }
    
    Write-Output "- A Verificação em Tempo Real está habilitada? $OnAccessScanningEnabled"
    
    # Vamos descobrir o número da versão
    $FormattedAVVersion = (Get-ItemPropertyValue -Path "${strKasperskyKES8AVDatePath}settings\def\" -Name "SettingsVersion")
    Write-Output "- A versão do Kaspersky em execução é: $FormattedAVVersion"
}

# *************************************  
# Sub: ObtainKESServerData
# *************************************
function ObtainKESServerData {
    $strKasperskyKESServerAVDatePath = "Registry\KasperskyLab\Components\34\1103\1.0.0.0\Statistics\AVState\"
    $strKasperskyKESServerAVVersionPath = "Registry\KasperskyLab\WSEE\10.1\Install\"
  
    # Vamos descobrir o número da versão
    if (RegKeyExists "HKLM\$strKasperskyKESServerKeyPath\ProdVersion") {
        $FormattedAVVersion = (Get-ItemPropertyValue -Path "HKLM\$strKasperskyKESServerKeyPath" -Name "ProdVersion")
        Write-Output "- A versão do Kaspersky em execução é: $FormattedAVVersion"
    }
    elseif (RegKeyExists "HKLM\$strKasperskyKESServerAVVersionPath\Version") {
        $FormattedAVVersion = (Get-ItemPropertyValue -Path "HKLM\$strKasperskyKESServerAVVersionPath" -Name "Version")
        Write-Output "- A versão do Kaspersky em execução é: $FormattedAVVersion"
    }
    else {
        Write-Output "- Não foi possível encontrar qual versão do Kaspersky está sendo executada neste PC."
        $FormattedAVVersion = "Desconhecido"
    }

    if (RegKeyExists "HKLM\$strKasperskyKESServerAVDatePath\Protection_BasesDate") {
        $AVDatVersion = (Get-ItemPropertyValue -Path "HKLM\$strKasperskyKESServerAVDatePath" -Name "Protection_BasesDate")
        if ($AVDatVersion.Length -eq 0) {
            Write-Output "- A idade das definições de A/V do Kaspersky não foi encontrada no registro; verificando o arquivo XML em vez disso."
            
            # Obter os dados do arquivo de texto do caminho de instalação do A/V
            $InstallLocation = "C:\Program Files"
            $path = $InstallLocation + "\Kaspersky Lab\KES10SP1\Data\U1313g.xml"
            if (!(Test-Path $path)) {
                $path = $InstallLocation + "\Kaspersky Lab\KES10SP2\Data\U1313g.xml"
                if (!(Test-Path $path)) {
                    $path = $InstallLocation + "\Kaspersky Lab\KES10SP3\Data\U1313g.xml"
                    if (!(Test-Path $path)) {
                        Write-Output "- ERRO - Arquivo Ux do Kaspersky não encontrado"
                        return
                    }
                }
            }

            $AVDatVersion = (Get-Item $path).LastWriteTime
            Write-Output "- O arquivo foi modificado pela última vez em: $AVDatVersion"
            Write-Output "- A data atual é: $(Get-Date)"
            $CalculatedPatternAge = (Get-Date).Subtract($AVDatVersion).Days
            Write-Output "- A última vez que o Kaspersky foi atualizado foi há $CalculatedPatternAge dias."
        }
        else {
            # Se o valor do registro não for nulo, vamos usá-lo para determinar as informações
            $RawAVDate = $AVDatVersion.Substring(0, 10)
            $FormattedPatternAge = [datetime]::ParseExact($RawAVDate, "dd.MM.yyyy", $null)

            Write-Output "- A data atual é: $(Get-Date)"
            Write-Output "- De acordo com a Kaspersky, as definições de A/V foram atualizadas pela última vez em: $FormattedPatternAge"
            $CalculatedPatternAge = (Get-Date).Subtract($FormattedPatternAge).Days
            Write-Output "- A última vez que o Kaspersky foi atualizado foi há $CalculatedPatternAge dias."
        }
    }

    CalculateAVAge # Chamar a função para determinar a idade das definições de A/V

    # Vamos determinar se a Verificação em Tempo Real está habilitada ou não
    if (RegKeyExists "HKLM\$strKasperskyKESServerAVDatePath\Protection_BasesDate") {
        Write-Output "- Esta instalação do Kaspersky é gerenciada por um servidor KES."
        $RawOnAccessScanningEnabled = (Get-ItemPropertyValue -Path "HKLM\$strKasperskyKESServerAVDatePath" -Name "Protection_RtpState")
        # Valores abaixo foram obtidos de https://support.kaspersky.com/13758
        if ($RawOnAccessScanningEnabled -eq 4 -or $RawOnAccessScanningEnabled -eq 5 -or $RawOnAccessScanningEnabled -eq 6 -or $RawOnAccessScanningEnabled -eq 7 -or $RawOnAccessScanningEnabled -eq 8) {
            $OnAccessScanningEnabled = $true
        }
        else {
            $OnAccessScanningEnabled = $false


            # *************************************  
# Sub: ObtainKasperskySOSData
# *************************************
function ObtainKasperskySOSData {
    $strKasperskyKESServerAVDatePath = "Registry\KasperskyLab\protected\AVP9\"
    $AVDatVersion = (Get-ItemPropertyValue -Path "HKLM\$strKasperskyKESServerAVDatePath\Data" -Name "LastSuccessfulUpdate")
}

# *************************************  
# Sub: ObtainKasperskySOSData
# *************************************
function ObtainKasperskySOSData {
    $strKasperskyKESServerAVDatePath = "Registry\KasperskyLab\protected\AVP9\"
    $AVDatVersion = (Get-ItemPropertyValue -Path "HKLM\$strKasperskyKESServerAVDatePath\Data" -Name "LastSuccessfulUpdate")
  
    # The AVDatVersion value is a UNIX timestamp - so this script needs to convert it to a human-readable format before continuing.
    $FormattedPatternAge = [datetime]::FromFileTime($AVDatVersion)
    $CalculatedPatternAge = (Get-Date) - $FormattedPatternAge

    Write-Output "The current date is: $(Get-Date)"
    Write-Output "- The last time Kaspersky was updated was on $FormattedPatternAge, which was $CalculatedPatternAge days ago."
    
    CalculateAVAge # Call the function to determine how old the A/V Definitions are
    
    $RawOnAccessScanningEnabled = (Get-ItemPropertyValue -Path "HKLM\$strKasperskyKESServerAVDatePath" -Name "Enabled")
    if ($RawOnAccessScanningEnabled -eq 1) {
        $OnAccessScanningEnabled = $true
    } else {
        $OnAccessScanningEnabled = $false
    }
    $OnAccessScanningEnabled = $true
    Write-Output "- Is Real Time Scanning Enabled? $OnAccessScanningEnabled"
  
    # Let's figure out the version number
    $FormattedAVVersion = (Get-ItemPropertyValue -Path "HKLM\$strKasperskyKESServerAVDatePath\environment" -Name "ProductVersion")
    Write-Output "- The version of Kaspersky running is: $FormattedAVVersion"
}

# *************************************  
# Sub: ObtainKasperskySO3Data
# *************************************
function ObtainKasperskySO3Data {
    $strKasperskyKESServerAVDatePath = "Registry\KasperskyLab\protected\KSOS13"
    $AVDatVersion = (Get-ItemPropertyValue -Path "HKLM\$strKasperskyKESServerAVDatePath\Data" -Name "LastSuccessfulUpdate")

    # The AVDatVersion value is a UNIX timestamp - so this script needs to convert it to a human-readable format before continuing.
    $FormattedPatternAge = [datetime]::FromFileTime($AVDatVersion)
    $CalculatedPatternAge = (Get-Date) - $FormattedPatternAge

    Write-Output "The current date is: $(Get-Date)"
    Write-Output "- The last time Kaspersky was updated was on $FormattedPatternAge, which was $CalculatedPatternAge days ago."

    CalculateAVAge # Call the function to determine how old the A/V Definitions are

    $RawOnAccessScanningEnabled = (Get-ItemPropertyValue -Path "HKLM\$strKasperskyKESServerAVDatePath" -Name "Enabled")
    if ($RawOnAccessScanningEnabled -eq 1) {
        $OnAccessScanningEnabled = $true
    } else {
        $OnAccessScanningEnabled = $false
    }
    Write-Output "- Is Real Time Scanning Enabled? $OnAccessScanningEnabled"

    # Let's figure out the version number
    $FormattedAVVersion = (Get-ItemPro
