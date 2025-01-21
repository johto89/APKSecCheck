param(
    [Parameter(Mandatory=$true)]
    [string]$SourcePath,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = ".\scan_results"
)

$patterns = @{
    "API Keys" = @(
        'apikey\s*=\s*[''"][0-9a-zA-Z\-]{20,}[''"]',
        'api_key\s*=\s*[''"][0-9a-zA-Z\-]{20,}[''"]',
        'apiSecret\s*=\s*[''"][0-9a-zA-Z\-]{20,}[''"]'
    )
    "URLs & Endpoints" = @(
        '(https?:\/\/[^\s<>"'']+|www\.[^\s<>"'']+)',
        '\/api\/[a-zA-Z0-9\/_-]+',
        '\/v[0-9]+\/[a-zA-Z0-9\/_-]+'
    )
    "Authentication" = @(
        'password\s*=\s*[''"][^''"]+[''"]',
        'passwd\s*=\s*[''"][^''"]+[''"]',
        'credentials\s*=\s*[''"][^''"]+[''"]',
        'auth_token\s*=\s*[''"][^''"]+[''"]',
        'oauth\s*=\s*[''"][^''"]+[''"]'
    )
    "IP Addresses" = @(
        # Standard IPv4
        '\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
        # IPv4 with port
        '\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{1,5}\b',
        # IPv4 ranges
        '\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}\b',
        # IPv4 in URL format
        'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
        # IPv6 standard format
        '(?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4}',
        # IPv6 compressed format
        '(?:[A-F0-9]{1,4}:){0,7}:(?:[A-F0-9]{1,4}:){0,7}[A-F0-9]{1,4}',
        # IPv6 with port
        '\[(?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4}\]:\d{1,5}',
        # Localhost references
        'localhost:\d{1,5}',
        '127\.0\.0\.1(:\d{1,5})?'
    )
    "Internal Network Patterns" = @(
        # Private IPv4 ranges
        '\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
        '\b172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}\b',
        '\b192\.168\.\d{1,3}\.\d{1,3}\b',
        # Link-local addresses
        '\b169\.254\.\d{1,3}\.\d{1,3}\b',
        # Multicast addresses
        '\b224\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
        '\b239\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
    )
    "Network Configuration" = @(
        # Common network configuration patterns
        'gateway\s*=\s*[''"][^''"]+[''"]',
        'subnet\s*=\s*[''"][^''"]+[''"]',
        'netmask\s*=\s*[''"][^''"]+[''"]',
        'broadcast\s*=\s*[''"][^''"]+[''"]',
        'dhcp\s*=\s*[''"][^''"]+[''"]',
        'dns\s*=\s*[''"][^''"]+[''"]',
        # Interface configurations
        'eth[0-9]+|wlan[0-9]+|bond[0-9]+',
        'interface\s*=\s*[''"][^''"]+[''"]'
    )
    "Sensitive Data" = @(
        '\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b', # Email addresses
        '(\b|\d+)[A-F0-9]{32}(\b|\d+)',                        # MD5 hashes
        '(\b|\d+)[A-F0-9]{40}(\b|\d+)',                        # SHA1 hashes
        '(\b|\d+)[A-F0-9]{64}(\b|\d+)'                         # SHA256 hashes
    )
    "AWS Related" = @(
        'AKIA[0-9A-Z]{16}',                                     # AWS Access Key ID
        '[0-9a-zA-Z/+]{40}',                                   # AWS Secret Access Key
        'arn:aws:[a-zA-Z0-9\-]+:[a-zA-Z0-9\-]+:[0-9]+:.+'    # AWS ARN
    )
    "Database" = @(
        'jdbc:[a-zA-Z]+:\/\/[^\s;"]+',
        'mongodb:\/\/[^\s;"]+',
        'postgresql:\/\/[^\s;"]+',
        'mysql:\/\/[^\s;"]+',
        'redis:\/\/[^\s;"]+',
        'connection_string\s*=\s*[''"][^''"]+[''"]'
    )
    "Certificates & Keys" = @(
        '-----BEGIN [A-Z ]+ PRIVATE KEY-----',
        '-----BEGIN [A-Z ]+ PUBLIC KEY-----',
        '-----BEGIN CERTIFICATE-----'
    )
}

function Write-ColorOutput($ForegroundColor) {
    $fc = $host.UI.RawUI.ForegroundColor
    $host.UI.RawUI.ForegroundColor = $ForegroundColor
    if ($args) {
        Write-Output $args
    }
    $host.UI.RawUI.ForegroundColor = $fc
}

function Initialize-ScanEnvironment {
    if (!(Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath | Out-Null
    }
    
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $scanDir = Join-Path $OutputPath "scan_$timestamp"
    New-Item -ItemType Directory -Path $scanDir | Out-Null
    return $scanDir
}

function Search-Patterns {
    param (
        [string]$ScanDir,
        [string]$SourcePath
    )

    $results = @{}
    $totalFindings = 0

    Write-ColorOutput Green "[+] Starting security scan of decompiled APK source..."
    Write-ColorOutput Yellow "[*] Source directory: $SourcePath"
    
    foreach ($category in $patterns.Keys) {
        $findings = @()
        Write-ColorOutput Cyan "[+] Scanning for $category..."
        
        foreach ($pattern in $patterns[$category]) {
            $matches = Get-ChildItem -Path $SourcePath -Recurse -File | 
                      Select-String -Pattern $pattern -AllMatches
            
            foreach ($match in $matches) {
                $findings += [PSCustomObject]@{
                    File = $match.Path.Replace($SourcePath, '')
                    Line = $match.LineNumber
                    Match = $match.Line.Trim()
                    Pattern = $pattern
                }
            }
        }
        
        if ($findings.Count -gt 0) {
            $results[$category] = $findings
            $totalFindings += $findings.Count
            Write-ColorOutput Yellow "    Found $($findings.Count) potential matches"
            
            # Export category findings to CSV
            $categoryFile = Join-Path $ScanDir "$($category.Replace(' ', '_')).csv"
            $findings | Export-Csv -Path $categoryFile -NoTypeInformation
        }
    }

    # Generate summary report
    $summaryFile = Join-Path $ScanDir "scan_summary.txt"
    
    # Create summary header
    $summaryContent = @"
APK Source Code Security Scan Summary
===================================
Scan Date: $(Get-Date)
Source Path: $SourcePath
Total Findings: $totalFindings

Findings by Category:
"@
    
    # Add category findings
    foreach ($category in $results.Keys) {
        $summaryContent += "`n- {0}: {1} findings" -f $category, $results[$category].Count
    }
    
    # Add IP analysis section
    $summaryContent += @"

IP Address Analysis:
-------------------
- Found standard IPv4 addresses: $($results['IP Addresses'].Count)
- Found internal network addresses: $($results['Internal Network Patterns'].Count)
- Network configuration entries: $($results['Network Configuration'].Count)

Review the individual CSV files for detailed findings in each category.
Note: All findings should be manually verified as they may include false positives.
"@

    # Write summary to file
    $summaryContent | Set-Content $summaryFile

    Write-ColorOutput Green "[+] Scan complete! Results saved to: $ScanDir"
    Write-ColorOutput Yellow "[*] Total findings: $totalFindings"
    Write-ColorOutput Yellow "[*] Review the scan_summary.txt file and category-specific CSVs for details"
}

# Main execution
$scanDir = Initialize-ScanEnvironment
Search-Patterns -ScanDir $scanDir -SourcePath $SourcePath