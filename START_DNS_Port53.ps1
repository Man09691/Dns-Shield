# START_DNS_Port53.ps1
# Sets primary DNS server to 127.0.0.1 and launches DNS Shield Port 53
Write-Host "Setting DNS Server to 127.0.0.1..." -ForegroundColor Cyan
try {
    $adapters = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' }
    foreach ($adapter in $adapters) {
        Set-DnsClientServerAddress -InterfaceIndex $adapter.InterfaceIndex -ServerAddresses ("127.0.0.1") -ErrorAction SilentlyContinue
    }
} catch {
    Write-Host "Note: Administrator privileges required to change adapter DNS." -ForegroundColor Yellow
}

Write-Host "Starting DNS Shield on port 53..." -ForegroundColor Green
python main.py
