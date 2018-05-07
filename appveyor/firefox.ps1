# License: CC0 1.0 Universal: http://creativecommons.org/publicdomain/zero/1.0/

function InstallFirefox ($architecture) {
    if ($architecture -eq "32") {
        $args = "--x86"
    }
    # We need to remove any system firefox first
    Write-Host "Removing existing Firefox"
    Start-Process -FilePath "C:\Program Files (x86)\Mozilla Firefox\uninstall\helper.exe" -ArgumentList "/S" -Wait -Passthru
    # In order to be able to install 32 or 64bits versions
    Write-Host "Installing Firefox matching target architecture $architecture"
    choco install $args firefox
}

function main () {
    InstallFirefox $env:PYTHON_ARCH
}

main
