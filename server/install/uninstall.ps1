# Desinstallation du client AuxiPak (Windows).
#
#   irm @@AUXIPAK_URL@@/uninstall.ps1 | iex
#
# Retire auxipak.exe et auxipak-builder.exe et leur entree du PATH (console
# administrateur : installation systeme ; sinon : installation utilisateur).
# Option : $env:AUXIPAK_PURGE = "1" supprime aussi configuration, registre,
# cache et journaux. Les applications installees par AuxiPak ne sont jamais
# supprimees par ce script : retirez-les d'abord avec "auxipak remove".
# Langue des messages : $env:AUXIPAK_LANG (fr, en), sinon celle de Windows.
#
# Ce fichier est volontairement en ASCII (compatibilite PowerShell 5.1).

function Uninstall-AuxiPak {
    $ErrorActionPreference = 'Stop'
    $Purge = ($env:AUXIPAK_PURGE -eq '1')
    $fr = if ($env:AUXIPAK_LANG) { $env:AUXIPAK_LANG -like 'fr*' } else { (Get-UICulture).TwoLetterISOLanguageName -eq 'fr' }
    # Message dans la langue de l'utilisateur (francais sans accents : ASCII).
    function Msg([string]$f, [string]$e) { if ($fr) { $f } else { $e } }

    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    $isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if ($isAdmin) {
        $root = Join-Path $env:ProgramData 'AuxiPak'
        $binDir = Join-Path $env:ProgramFiles 'AuxiPak\bin'
        $pathScope = 'Machine'
    } else {
        $root = Join-Path $env:LOCALAPPDATA 'AuxiPak'
        $binDir = Join-Path $env:LOCALAPPDATA 'AuxiPak\bin'
        $pathScope = 'User'
        Write-Host (Msg "Desinstallation pour l'utilisateur courant (console non administrateur)." "Uninstalling for the current user (non-administrator console).")
    }

    $exe = Join-Path $binDir 'auxipak.exe'
    if ((Test-Path -LiteralPath $exe) -and (Test-Path -LiteralPath (Join-Path $root 'state\registry.json'))) {
        Write-Host (Msg "Applications encore enregistrees (elles resteront installees) :" "Applications still registered (they will stay installed):")
        $ErrorActionPreference = 'Continue'
        try { & $exe list } catch { }
        $ErrorActionPreference = 'Stop'
        Write-Host ""
    }

    foreach ($b in @('auxipak.exe', 'auxipak-builder.exe')) {
        $f = Join-Path $binDir $b
        if (Test-Path -LiteralPath $f) {
            Remove-Item -LiteralPath $f -Force
            Write-Host (Msg "Supprime : $f" "Deleted: $f")
        }
    }
    if ((Test-Path -LiteralPath $binDir) -and -not (Get-ChildItem -LiteralPath $binDir -Force)) {
        Remove-Item -LiteralPath $binDir -Force
    }

    $current = [Environment]::GetEnvironmentVariable('Path', $pathScope)
    if ($current) {
        $parts = $current.Split(';') | Where-Object { $_ -ne '' -and $_.TrimEnd('\') -ine $binDir.TrimEnd('\') }
        $new = ($parts -join ';')
        if ($new -ne $current) {
            [Environment]::SetEnvironmentVariable('Path', $new, $pathScope)
            Write-Host (Msg "Retire du PATH ($pathScope) : $binDir" "Removed from PATH ($pathScope): $binDir")
        }
    }

    if ($Purge) {
        # Les donnees et applications (data, apps) sont conservees.
        foreach ($d in @('config', 'state', 'cache', 'log')) {
            $p = Join-Path $root $d
            if (Test-Path -LiteralPath $p) { Remove-Item -LiteralPath $p -Recurse -Force }
        }
        if ((Test-Path -LiteralPath $root) -and -not (Get-ChildItem -LiteralPath $root -Force)) {
            Remove-Item -LiteralPath $root -Force
        }
        Write-Host (Msg "Configuration, registre, cache et journaux supprimes." "Configuration, registry, cache and logs deleted.")
    } else {
        Write-Host (Msg "Configuration conservee ($root) : `$env:AUXIPAK_PURGE = '1' pour la supprimer." "Configuration kept ($root): set `$env:AUXIPAK_PURGE = '1' to delete it.")
    }
    Write-Host (Msg "AuxiPak est desinstalle." "AuxiPak is uninstalled.")
    # Succes : ne pas laisser le code de sortie d'une commande interne.
    $global:LASTEXITCODE = 0
}

Uninstall-AuxiPak
