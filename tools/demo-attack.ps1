<#
Q-Lure live demo menu.

Run this on the machine where `docker compose up -d --build` is already running
(decoys on 127.0.0.1). Each option below is a real, small step of one attack,
against your own decoy stack only. Pick steps one at a time during a live demo
and watch http://127.0.0.1:9000 update as you go. Nothing here is automated
end to end on purpose: you control the pace.
Steps 4, 11 and 12 need the Docker SSH and banner decoys. The other steps also work
with only the web and API decoys (uvicorn), see docs/DEMO.md "Option C".

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
    Write-Host "7) SQL injection probe   - injection pattern on the web page (R5)"
    Write-Host "8) Path traversal probe  - read a file outside the web root"
    Write-Host "9) Scanner user agent    - same page, with a scanner's browser string"
    Write-Host "10) Show cmd.exe curl commands for the audience"
    Write-Host "11) FTP login attempts   - three failed FTP logins (logged; default pairs such as admin:admin fire R4)"
    Write-Host "12) Database Probes      - probe MySQL and Redis ports"
    Write-Host "A) Run All Automated     - runs 1, 2, 3, 7, 8, 9, 11, 12 in one go"
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
    Write-Host "Done. Check the dashboard: R2 (path enumeration) should fire on this web session. Alone it scores 25, which is Benign." -ForegroundColor Yellow
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
    Write-Host "Done. Check the dashboard: R3 (brute force) should fire on this session. Alone it scores 30, which is Suspicious." -ForegroundColor Yellow
}

function Step-FindLeak {
    Write-Host "`n[Find the leaked file] reading $WebBase/backup/config.bak ..." -ForegroundColor Cyan
    $content = (curl.exe -s "$WebBase/backup/config.bak") -join "`n"
    Write-Host $content
    if ($content -match "password\s*=\s*(\S+)") {
        $script:LeakedPassword = $Matches[1]
        Write-Host "Leaked SSH password captured: $($script:LeakedPassword)" -ForegroundColor Green
    } else {
        Write-Host "Could not find a password in the response." -ForegroundColor Red
    }
    Write-Host "Check the dashboard: R9 (sensitive file access) should fire on this session." -ForegroundColor Yellow
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
    Write-Host "Back from SSH. Check the dashboard: R7 (honeytoken use) should fire on the SSH session." -ForegroundColor Yellow
}

function Step-UseApiKey {
    Write-Host "`n[Use stolen API key] paste the key you saw after 'X-API-Key:' in bash_history:" -ForegroundColor Cyan
    $key = Read-Host "API key"
    if (-not $key) { Write-Host "No key entered, skipping." -ForegroundColor Red; return }
    Write-Host "Calling $ApiBase/api/v1/users with that key ..."
    curl.exe -s -H "X-API-Key: $key" "$ApiBase/api/v1/users"
    Write-Host ""
    Write-Host "Check the dashboard: R7 (honeytoken use) should fire on this API session. If steps 1 to 4 ran first, the linked actor can reach R10 (kill-chain progression)." -ForegroundColor Yellow
}

function Step-Sqli {
    Write-Host "`n[SQL injection probe] sending an injection pattern to the web page (rule R5)" -ForegroundColor Cyan
    $code = curl.exe -s -o NUL -w "%{http_code}" "$WebBase/?id=1%27%20OR%20%271%27%3D%271"
    Write-Host "  GET /?id=1' OR '1'='1  -> $code"
    Write-Host "Done. Check the dashboard: R5 (injection pattern) should fire on this session. Alone it scores 40, which is Suspicious." -ForegroundColor Yellow
}

function Step-Traversal {
    Write-Host "`n[Path traversal probe] asking for a file outside the web root" -ForegroundColor Cyan
    $code = curl.exe -s -o NUL -w "%{http_code}" "$WebBase/download?file=../../../../etc/passwd"
    Write-Host "  GET /download?file=../../../../etc/passwd  -> $code"
    Write-Host "Done. Check the dashboard: R5 (traversal pattern) should fire on this session. There is no fake /download route yet (roadmap P1.3), so a 404 is expected." -ForegroundColor Yellow
}

function Step-Scanner {
    Write-Host "`n[Scanner user agent] same page, with a scanner's browser string" -ForegroundColor Cyan
    $code = curl.exe -s -o NUL -w "%{http_code}" -A "sqlmap/1.8#stable (https://sqlmap.org)" "$WebBase/"
    Write-Host "  GET /  with User-Agent sqlmap  -> $code"
    Write-Host "Done. Check the dashboard: R6 (scanner tool) should fire on this session." -ForegroundColor Yellow
}

function Step-FtpBanner {
    Write-Host "`n[FTP login attempts] connecting to the FTP decoy (port 2121) three times" -ForegroundColor Cyan
    $passwords = @("admin", "12345", "root")
    foreach ($pw in $passwords) {
        Write-Host "  Sending admin:$pw"
        curl.exe -s -o NUL "ftp://admin:$pw@127.0.0.1:2121/"
        Start-Sleep -Milliseconds 150
    }
    Write-Host "Done. Each attempt is logged as a login attempt and always fails (530). A default pair such as admin:admin fires R4; repeated failures across services add to R3." -ForegroundColor Yellow
}

function Step-MySqlRedis {
    Write-Host "`n[MySQL & Redis Probe] probing ports 3306 and 6379" -ForegroundColor Cyan
    Write-Host "  Connecting to MySQL (3306)..."
    try { $c1 = New-Object System.Net.Sockets.TcpClient("127.0.0.1", 3306); $c1.Close() } catch {}
    Write-Host "  Connecting to Redis (6379)..."
    try { $c2 = New-Object System.Net.Sockets.TcpClient("127.0.0.1", 6379); $c2.Close() } catch {}
    Write-Host "Done. R6 (banner grab with no follow-up) should fire on these sessions if nothing was sent. No rule is specific to MySQL or Redis yet." -ForegroundColor Yellow
}

function Step-AllInOne {
    Write-Host "`n[Running All Automated Scenarios]" -ForegroundColor Magenta
    Step-Recon
    Step-BruteForce
    Step-FindLeak
    Step-Sqli
    Step-Traversal
    Step-Scanner
    Step-FtpBanner
    Step-MySqlRedis
    Write-Host "`nAll automated scenarios complete! Refresh your dashboard." -ForegroundColor Green
}

function Show-CmdCommands {
    Write-Host "`nCopy these into Command Prompt (cmd.exe). Each line is one step:" -ForegroundColor Magenta
    Write-Host '  curl.exe -s -o NUL -w "%{http_code}" http://127.0.0.1:8080/login'
    Write-Host '  curl.exe -s http://127.0.0.1:8080/backup/config.bak'
    Write-Host '  curl.exe -s -o NUL -w "%{http_code}" "http://127.0.0.1:8080/?id=1%27%20OR%20%271%27%3D%271"'
    Write-Host '  curl.exe -s -o NUL -w "%{http_code}" "http://127.0.0.1:8080/download?file=../../../../etc/passwd"'
    Write-Host '  curl.exe -s -o NUL -w "%{http_code}" -A "sqlmap/1.8#stable" http://127.0.0.1:8080/'
    Write-Host '  curl.exe -s -H "X-API-Key: qlk_decoy_7f3a9c21e5d84b0a" http://127.0.0.1:8081/api/v1/users'
    Write-Host "In cmd.exe, use %% instead of % only inside .bat files; at the prompt, a single % works." -ForegroundColor DarkGray
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
        "7" { Step-Sqli }
        "8" { Step-Traversal }
        "9" { Step-Scanner }
        "10" { Show-CmdCommands }
        "11" { Step-FtpBanner }
        "12" { Step-MySqlRedis }
        "A" { Step-AllInOne }
        "a" { Step-AllInOne }
        "0" { break menu }
        default { Write-Host "Pick a valid option from the menu." -ForegroundColor Red }
    }
}
