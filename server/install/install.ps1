# Installation du client AuxiPak (Windows 10/11, x64 et ARM64).
#
#   irm @@AUXIPAK_URL@@/install.ps1 | iex
#
# Dans une console PowerShell "Executer en tant qu'administrateur" :
# installation pour tous les utilisateurs (Program Files, PATH systeme).
# Sinon : installation pour l'utilisateur courant (%LOCALAPPDATA%\AuxiPak).
# Option : $env:AUXIPAK_WITH_BUILDER = "1" installe aussi auxipak-builder.
# Langue des messages : $env:AUXIPAK_LANG (fr, en), sinon celle de Windows.
#
# Ce fichier est volontairement en ASCII (compatibilite PowerShell 5.1).

function Install-AuxiPak {
    $ErrorActionPreference = 'Stop'
    $ProgressPreference = 'SilentlyContinue'
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

    $Url = '@@AUXIPAK_URL@@'
    $RootSha256 = '@@ROOT_SHA256@@'
    $WithBuilder = ($env:AUXIPAK_WITH_BUILDER -eq '1')
    $fr = if ($env:AUXIPAK_LANG) { $env:AUXIPAK_LANG -like 'fr*' } else { (Get-UICulture).TwoLetterISOLanguageName -eq 'fr' }
    # Message dans la langue de l'utilisateur (francais sans accents : ASCII).
    function Msg([string]$f, [string]$e) { if ($fr) { $f } else { $e } }

    # Architecture du systeme (et non du processus PowerShell).
    $arch = $null
    try {
        $arch = [string][System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture
    } catch { }
    if (-not $arch) {
        $arch = if ($env:PROCESSOR_ARCHITEW6432) { $env:PROCESSOR_ARCHITEW6432 } else { $env:PROCESSOR_ARCHITECTURE }
    }
    switch -Regex ($arch) {
        '^(X64|AMD64)$' { $platform = 'windows-x86_64' }
        '^(Arm64|ARM64)$' { $platform = 'windows-arm64' }
        default { throw (Msg "Architecture non prise en charge : $arch" "Unsupported architecture: $arch") }
    }

    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    $isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if ($isAdmin) {
        $binDir = Join-Path $env:ProgramFiles 'AuxiPak\bin'
        $confDir = Join-Path $env:ProgramData 'AuxiPak\config'
        $pathScope = 'Machine'
    } else {
        $binDir = Join-Path $env:LOCALAPPDATA 'AuxiPak\bin'
        $confDir = Join-Path $env:LOCALAPPDATA 'AuxiPak\config'
        $pathScope = 'User'
        Write-Host (Msg "Installation pour l'utilisateur courant (console non administrateur)." "Installing for the current user (non-administrator console).")
    }

    Write-Host (Msg "AuxiPak : installation depuis $Url ($platform)" "AuxiPak: installing from $Url ($platform)")
    $tmp = Join-Path ([IO.Path]::GetTempPath()) ("auxipak-" + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $tmp | Out-Null
    try {
        # Choix de l'archive dans SHA256SUMS.
        $sumsFile = Join-Path $tmp 'SHA256SUMS'
        try {
            Invoke-WebRequest -UseBasicParsing -Uri "$Url/downloads/SHA256SUMS" -OutFile $sumsFile
        } catch {
            throw (Msg "Aucun client publie sur $Url (downloads/SHA256SUMS introuvable)" "No client published on $Url (downloads/SHA256SUMS not found)")
        }
        $pattern = '^([0-9a-fA-F]{64})\s+\*?(auxipak-[A-Za-z0-9._-]+-' + [Regex]::Escape($platform) + '\.zip)\s*$'
        $match = $null
        foreach ($l in (Get-Content -LiteralPath $sumsFile)) {
            $m = [Regex]::Match($l, $pattern)
            if ($m.Success) { $match = $m }
        }
        if (-not $match) { throw (Msg "Aucun client disponible pour $platform" "No client available for $platform") }
        $expected = $match.Groups[1].Value
        $file = $match.Groups[2].Value

        Write-Host (Msg "Telechargement de $file" "Downloading $file")
        $zip = Join-Path $tmp $file
        Invoke-WebRequest -UseBasicParsing -Uri "$Url/downloads/$file" -OutFile $zip
        $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $zip).Hash
        if ($actual -ne $expected) {
            throw (Msg "Empreinte SHA-256 invalide pour $file (attendu $expected, obtenu $actual)" "Invalid SHA-256 fingerprint for $file (expected $expected, got $actual)")
        }
        Write-Host (Msg "Empreinte SHA-256 verifiee" "SHA-256 fingerprint verified")

        $x = Join-Path $tmp 'x'
        Expand-Archive -LiteralPath $zip -DestinationPath $x -Force
        $src = Join-Path $x ([IO.Path]::GetFileNameWithoutExtension($file))
        if (-not (Test-Path -LiteralPath (Join-Path $src 'auxipak.exe'))) { throw (Msg "Archive invalide : auxipak.exe absent" "Invalid archive: auxipak.exe missing") }

        # Binaires
        New-Item -ItemType Directory -Force -Path $binDir | Out-Null
        Copy-Item -LiteralPath (Join-Path $src 'auxipak.exe') -Destination $binDir -Force
        Write-Host (Msg "Installe : $binDir\auxipak.exe" "Installed: $binDir\auxipak.exe")
        if ($WithBuilder) {
            if (-not (Test-Path -LiteralPath (Join-Path $src 'auxipak-builder.exe'))) { throw (Msg "Archive invalide : auxipak-builder.exe absent" "Invalid archive: auxipak-builder.exe missing") }
            Copy-Item -LiteralPath (Join-Path $src 'auxipak-builder.exe') -Destination $binDir -Force
            Write-Host (Msg "Installe : $binDir\auxipak-builder.exe" "Installed: $binDir\auxipak-builder.exe")
        }

        # PATH
        $current = [Environment]::GetEnvironmentVariable('Path', $pathScope)
        $parts = @()
        if ($current) { $parts = $current.Split(';') | Where-Object { $_ -ne '' } }
        if (-not ($parts | Where-Object { $_.TrimEnd('\') -ieq $binDir.TrimEnd('\') })) {
            [Environment]::SetEnvironmentVariable('Path', (($parts + $binDir) -join ';'), $pathScope)
            Write-Host (Msg "Ajoute au PATH ($pathScope) : $binDir" "Added to PATH ($pathScope): $binDir")
        }
        if (-not (($env:Path.Split(';')) | Where-Object { $_.TrimEnd('\') -ieq $binDir.TrimEnd('\') })) {
            $env:Path = "$env:Path;$binDir"
        }

        # Ancres de confiance du depot officiel (publiques).
        $trustDir = Join-Path $confDir 'trust\official'
        New-Item -ItemType Directory -Force -Path $trustDir | Out-Null
        [IO.File]::WriteAllBytes((Join-Path $trustDir 'root.json'), [Convert]::FromBase64String('@@ROOT_B64@@'))
        [IO.File]::WriteAllBytes((Join-Path $trustDir 'package-keys.json'), [Convert]::FromBase64String('@@KEYS_B64@@'))

        # Configuration (conservee si elle existe deja).
        $configFile = Join-Path $confDir 'config.toml'
        if (Test-Path -LiteralPath $configFile) {
            Write-Host (Msg "Configuration existante conservee : $configFile" "Existing configuration kept: $configFile")
        } else {
            $text = @(
                '# AuxiPak client configuration (created by install.ps1).',
                'cache_ttl_seconds = 3600',
                '',
                '[[repository]]',
                'name = "official"',
                "url = `"$Url/repos/official/`"",
                'root = "trust/official/root.json"',
                'package_keys = "trust/official/package-keys.json"',
                'official = true',
                $(if ($Url.StartsWith('http://')) { 'allow_insecure_localhost = true' } else { '' }),
                ''
            ) -join "`n"
            [IO.File]::WriteAllText($configFile, $text, (New-Object Text.UTF8Encoding($false)))
            Write-Host (Msg "Configuration creee : $configFile" "Configuration created: $configFile")
        }

        Write-Host ""
        Write-Host (Msg "Empreinte de la racine de confiance : $RootSha256" "Trust root fingerprint: $RootSha256")
        # PowerShell 5.1 : une sortie d'erreur redirigee deviendrait une
        # exception avec ErrorActionPreference = Stop.
        $synced = $false
        $ErrorActionPreference = 'Continue'
        try {
            & (Join-Path $binDir 'auxipak.exe') update *> $null
            $synced = ($LASTEXITCODE -eq 0)
        } catch { }
        $ErrorActionPreference = 'Stop'
        if ($synced) {
            Write-Host (Msg "Index du depot officiel synchronise." "Official repository index synchronized.")
        } else {
            Write-Host (Msg "Synchronisation a faire : auxipak update" "Synchronization pending: auxipak update")
        }
        Write-Host ""
        Write-Host (Msg "AuxiPak est installe. Exemples :" "AuxiPak is installed. Examples:")
        Write-Host "  auxipak search firefox"
        Write-Host "  auxipak install <application>"
        Write-Host (Msg "  auxipak set lang fr      # langue : fr ou en" "  auxipak set lang fr      # language: fr or en")
        Write-Host (Msg "Desinstallation : irm $Url/uninstall.ps1 | iex" "Uninstall: irm $Url/uninstall.ps1 | iex")
        # Succes : ne pas laisser le code de sortie d'une commande interne.
        $global:LASTEXITCODE = 0
    } finally {
        Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Install-AuxiPak
