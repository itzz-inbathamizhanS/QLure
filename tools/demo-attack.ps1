<#
Q-Lure live demo menu.

Run this on the machine where `docker compose up -d --build` is already running
(decoys on 127.0.0.1). Each option below is a real, small step of one attack,
against your own decoy stack only. Pick steps one at a time during a live demo
and watch http://127.0.0.1:9000 update as you go. Nothing here is automated
end to end on purpose: you control the pace.

Usage (Command Prompt or PowerShell):
    powershell -ExecutionPolicy Bypass -File tools\demo-attack.ps1
#>

$WebBase = "http://127.0.0.1:8080"
$ApiBase = "http://127.0.0.1:8081"
$SshHost = "127.0.0.1"
$SshPort = 2222

$script:LeakedPassword = $null

function Show-Menu {
    Write-Host ""
    Write-Host "==== Q-Lure live attack simulation ====" -ForegroundColor Magenta
    Write-Host "1) Recon scan            - probe common attack paths"
    Write-Host "2) Brute-force login     - try several passwords on /login"
    Write-Host "3) Find the leaked file  - read the leaked backup config"
    Write-Host "4) Use stolen SSH creds  - log in with the leaked password"
    Write-Host "5) Use stolen API key    - call the real API with a planted key"
    Write-Host "6) Show the dashboard URL"
    Write-Host "0) Exit"
    Write-Host ""
}

function Step-Recon {
    Write-Host "`n[Recon scan] probing common attack paths on $WebBase ..." -ForegroundColor Cyan
    $paths = @(
        "/wp-login.php", "/phpmyadmin/", "/.env", "/.git/config",
        "/xmlrpc.php", "/admin.php", "/vendor/phpunit", "/.aws", "/server-status"
    )
    foreach ($p in $paths) {
        $code = curl.exe -s -o NUL -w "%{http_code}" "$WebBase$p"
        Write-Host ("  GET {0,-18} -> {1}" -f $p, $code)
        Start-Sleep -Milliseconds 150
    }
    Write-Host "Done. Check the dashboard: this visitor should score as recon." -ForegroundColor Yellow
}

function Step-BruteForce {
    Write-Host "`n[Brute-force login] trying passwords against $WebBase/login ..." -ForegroundColor Cyan
    $passwords = @("admin123", "letmein123", "Summer2026", "qwerty123", "P@ssw0rd", "changeme99")
    foreach ($pw in $passwords) {
        $body = "username=ops&password=$pw"
        $code = curl.exe -s -o NUL -w "%{http_code}" -X POST -d $body "$WebBase/login"
        Write-Host ("  POST /login  ops / {0,-14} -> {1}" -f $pw, $code)
        Start-Sleep -Milliseconds 150
    }
    Write-Host "Done. Check the dashboard: repeated failed logins from one visitor should flag." -ForegroundColor Yellow
}

function Step-FindLeak {
    Write-Host "`n[Find the leaked file] reading $WebBase/backup/config.bak ..." -ForegroundColor Cyan
    $content = curl.exe -s "$WebBase/backup/config.bak"
    Write-Host $content
    if ($content -match "password\s*=\s*(\S+)") {
        $script:LeakedPassword = $Matches[1]
        Write-Host "Leaked SSH password captured: $($script:LeakedPassword)" -ForegroundColor Green
    } else {
        Write-Host "Could not find a password in the response." -ForegroundColor Red
    }
    Write-Host "Check the dashboard: this file read should show as sensitive-file access." -ForegroundColor Yellow
}

function Step-UseSsh {
    if (-not $script:LeakedPassword) {
        Write-Host "Run option 3 first to get the leaked password." -ForegroundColor Red
        return
    }
    Write-Host "`n[Use stolen SSH credential] connecting to ${SshHost}:${SshPort} as 'deploy' ..." -ForegroundColor Cyan
    Write-Host "When prompted for a password, type:  $($script:LeakedPassword)" -ForegroundColor Green
    Write-Host "Once inside, try:  whoami   id   ls   cat ~/.bash_history   exit" -ForegroundColor Green
    ssh.exe -o StrictHostKeyChecking=no -o UserKnownHostsFile=NUL -p $SshPort deploy@$SshHost
    Write-Host "Back from SSH. Check the dashboard: this session should show the honeytoken use." -ForegroundColor Yellow
}

function Step-UseApiKey {
    Write-Host "`n[Use stolen API key] paste the key you saw after 'X-API-Key:' in bash_history:" -ForegroundColor Cyan
    $key = Read-Host "API key"
    if (-not $key) { Write-Host "No key entered, skipping." -ForegroundColor Red; return }
    Write-Host "Calling $ApiBase/api/v1/users with that key ..."
    curl.exe -s -H "X-API-Key: $key" "$ApiBase/api/v1/users"
    Write-Host ""
    Write-Host "Check the dashboard: the web leak, SSH session and this API call now link into one actor - the full kill chain." -ForegroundColor Yellow
}

:menu while ($true) {
    Show-Menu
    $choice = Read-Host "Pick a step"
    switch ($choice) {
        "1" { Step-Recon }
        "2" { Step-BruteForce }
        "3" { Step-FindLeak }
        "4" { Step-UseSsh }
        "5" { Step-UseApiKey }
        "6" { Write-Host "Dashboard: http://127.0.0.1:9000" -ForegroundColor Green }
        "0" { break menu }
        default { Write-Host "Pick a number from the menu." -ForegroundColor Red }
    }
}
