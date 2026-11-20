# STOP_Restore_Internet.ps1
# Restores DNS server settings to DHCP or public resolvers (8.8.8.8, 1.1.1.1)
Write-Host "Restoring Adapter DNS to automatic (DHCP) / Public Upstreams..." -ForegroundColor Cyan
try {
    $adapters = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' }
    foreach ($adapter in $adapters) {
        Set-DnsClientServerAddress -InterfaceIndex $adapter.InterfaceIndex -ResetServerAddresses -ErrorAction SilentlyContinue
    }
    Write-Host "DNS settings successfully restored." -ForegroundColor Green
} catch {
    Write-Host "Note: Run as Administrator to restore network adapter DNS." -ForegroundColor Yellow
}
