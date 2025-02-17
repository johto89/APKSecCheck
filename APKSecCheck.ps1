param(
    [Parameter(Mandatory=$true)]
    [string]$SourcePath,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = ".\scan_results"
)

# Define all vulnerability patterns
$patterns = @{
    "API Keys" = @(
        'apikey\s*=\s*[''"][0-9a-zA-Z\-]{20,}[''"]',
        'api_key\s*=\s*[''"][0-9a-zA-Z\-]{20,}[''"]',
        'apiSecret\s*=\s*[''"][0-9a-zA-Z\-]{20,}[''"]'
    )
    "URLs & Endpoints" = @(
        '(https?:\/\/[^\s<>"'']+|www\.[^\s<>"'']+)'
    )
    "Authentication" = @(
        'password\s*=\s*[''"][^''"]+[''"]',
        'passwd\s*=\s*[''"][^''"]+[''"]',
        'credentials\s*=\s*[''"][^''"]+[''"]',
        'auth_token\s*=\s*[''"][^''"]+[''"]',
        'oauth\s*=\s*[''"][^''"]+[''"]'
    )
    "IP Addresses" = @(
        '\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
        'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
        'localhost:\d{1,5}',
        '127\.0\.0\.1(:\d{1,5})?'
    )
    "Sensitive Data" = @(
        '\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b',
        '(\b|\d+)[A-F0-9]{32}(\b|\d+)',
        '(\b|\d+)[A-F0-9]{40}(\b|\d+)',
        '(\b|\d+)[A-F0-9]{64}(\b|\d+)'

        '-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----[\s\S]*?-----END\s+(?:RSA\s+)?PRIVATE\s+KEY-----',
        '-----BEGIN\s+(?:DSA\s+)?PRIVATE\s+KEY-----[\s\S]*?-----END\s+(?:DSA\s+)?PRIVATE\s+KEY-----',
        '-----BEGIN\s+(?:EC\s+)?PRIVATE\s+KEY-----[\s\S]*?-----END\s+(?:EC\s+)?PRIVATE\s+KEY-----',
        '-----BEGIN\s+OPENSSH\s+PRIVATE\s+KEY-----[\s\S]*?-----END\s+OPENSSH\s+PRIVATE\s+KEY-----',
        '-----BEGIN\s+PGP\s+PRIVATE\s+KEY\s+BLOCK-----[\s\S]*?-----END\s+PGP\s+PRIVATE\s+KEY\s+BLOCK-----'
    )
    "Intent and WebView" = @(
        'Intent\s*=\s*[^"]+',
        'startActivity\s*\([^)]*\)',
        'startService\s*\([^)]*\)',
        'sendBroadcast\s*\([^)]*\)',
        'startActivityForResult\s*\([^)]*\)',
        'webview\s*\.loadUrl\s*\([^)]*\)',       
        'webview\s*\.setWebViewClient\s*\([^)]*\)', 
        'webview\s*\.setJavaScriptEnabled\s*=\s*true', 
        'webview\s*\.addJavascriptInterface\s*\([^)]*\)'
    )
    "Provider" = @(
        'content\s*=\s*["''].*["'']\s*\(.+\)',
        'ContentProvider\s*\.query\s*\([^)]*\)',   
        'ContentResolver\s*\.query\s*\([^)]*\)',   
        'ContentProvider\s*\.insert\s*\([^)]*\)',  
        'ContentProvider\s*\.update\s*\([^)]*\)', 
        'ContentProvider\s*\.delete\s*\([^)]*\)'   
    )
    "Component Exports" = @(
        'android:exported\s*=\s*["'']true["'']',
        'intent-filter.*action.*android\.intent\.action\.',
        '<provider.*android:exported\s*=\s*["'']true["'']',
        '<activity.*android:exported\s*=\s*["'']true["'']',
        '<service.*android:exported\s*=\s*["'']true["'']',
        '<receiver.*android:exported\s*=\s*["'']true["'']'
    )
    "Intent Vulnerabilities" = @(
        'getIntent\(\)\.getExtras\(\)',
        'getIntent\(\)\.getStringExtra\(',
        'getIntent\(\)\.get\w+Extra\(',
        'android\.intent\.action\.SEND',
        'android\.intent\.action\.VIEW'
    )
    "Fragment Injection" = @(
        'Fragment\s+fragment\s*=\s*.+?\.instantiate\(',
        'getSupportFragmentManager\(\)\.findFragmentById\(',
        'getFragmentManager\(\)\.findFragmentById\(',
        'loadUrl\s*\(\s*"javascript:'
    )
    "SQL Injection" = @(
        'db\.rawQuery\s*\(',
        'db\.execSQL\s*\(',
        'SQLiteDatabase\.rawQuery\s*\(',
        'getReadableDatabase\(\)',
        'getWritableDatabase\(\)'
    )
    "Weak Manifest Permissions" = @(
        # Dangerous system permissions
        'android\.permission\.SYSTEM_ALERT_WINDOW',
        'android\.permission\.WRITE_SETTINGS',
        'android\.permission\.PACKAGE_USAGE_STATS',
        'android\.permission\.BIND_DEVICE_ADMIN',
        'android\.permission\.FACTORY_TEST',
    
        # Dangerous runtime permissions
        'android\.permission\.READ_CALENDAR',
        'android\.permission\.WRITE_CALENDAR',
        'android\.permission\.CAMERA',
        'android\.permission\.READ_CONTACTS',
        'android\.permission\.WRITE_CONTACTS',
        'android\.permission\.GET_ACCOUNTS',
        'android\.permission\.ACCESS_FINE_LOCATION',
        'android\.permission\.ACCESS_COARSE_LOCATION',
        'android\.permission\.ACCESS_BACKGROUND_LOCATION',
        'android\.permission\.RECORD_AUDIO',
        'android\.permission\.READ_PHONE_STATE',
        'android\.permission\.READ_PHONE_NUMBERS',
        'android\.permission\.CALL_PHONE',
        'android\.permission\.ANSWER_PHONE_CALLS',
        'android\.permission\.READ_CALL_LOG',
        'android\.permission\.WRITE_CALL_LOG',
        'android\.permission\.ADD_VOICEMAIL',
        'android\.permission\.USE_SIP',
        'android\.permission\.BODY_SENSORS',
        'android\.permission\.ACTIVITY_RECOGNITION',
        'android\.permission\.SEND_SMS',
        'android\.permission\.RECEIVE_SMS',
        'android\.permission\.READ_SMS',
        'android\.permission\.RECEIVE_WAP_PUSH',
        'android\.permission\.RECEIVE_MMS',
    
        # Weak protection levels
        '<permission[^>]+android:protectionLevel\s*=\s*[''"](?:normal|dangerous)[''"]',
        '<permission-group[^>]+android:protectionLevel\s*=\s*[''"](?:normal|dangerous)[''"]',
    
        # Improper component exposure
        '<(?:activity|service|receiver)[^>]+android:exported\s*=\s*[''"]true[''"][^>]*>(?!.*android:permission)',
        '<provider[^>]+android:exported\s*=\s*[''"]true[''"][^>]*>(?!.*android:readPermission)(?!.*android:writePermission)',
    
        # Debug/backup flags
        'android:debuggable\s*=\s*[''"]true[''"]',
        'android:allowBackup\s*=\s*[''"]true[''"]',
        'android:testOnly\s*=\s*[''"]true[''"]',
    
        # Implicit intent filters
        '<intent-filter>[^<]*<action\s+android:name\s*=\s*[''"]android\.intent\.action\.(?:MAIN|VIEW|SEND|PICK)[''"]'
    )
    "Insecure Root Check" = @(
        'RootTools\.isRootAvailable\(\)',
        'RootTools\.isAccessGiven\(\)',
        'eu\.chainfire\.libsuperuser',
        'com\.noshufou\.android\.su',
        'com\.thirdparty\.superuser', 
        'com\.koushikdutta\.superuser',
        'com\.zachspong\.temprootremovejb',
        'com\.ramdroid\.appquarantine'
    )
        "Insecure SSL/TLS Configuration" = @(
        'HttpsURLConnection\.setDefaultHostnameVerifier\(null\)',
        'Cipher\.getInstance\(\s*[''"](?:DES|DESede)(?:/\w+)*[''"]'
    )
}

function Write-ProgressBar {
    param (
        [int]$Current,
        [int]$Total,
        [string]$Category,
        [string]$CurrentFile,
        [int]$FileNumber,
        [int]$TotalFiles
    )
    
    # Ensure Current doesn't exceed Total
    $Current = [Math]::Min($Current, $Total)
    
    # Calculate percentage with bounds checking
    $percentComplete = [Math]::Min(100, [Math]::Round(($Current / [Math]::Max(1, $Total)) * 100))
    
    $progressBar = "["
    $barLength = 30
    $filledLength = [Math]::Round(($percentComplete / 100) * $barLength)
    
    for ($i = 0; $i -lt $barLength; $i++) {
        if ($i -lt $filledLength) {
            $progressBar += "="
        } else {
            $progressBar += " "
        }
    }

    # Smart file name truncation
    $fileName = Split-Path $CurrentFile -Leaf
    $maxFileLength = 40
    if ($fileName.Length -gt $maxFileLength) {
        $fileName = "..." + $fileName.Substring($fileName.Length - $maxFileLength)
    }

    # Ensure file numbers are within bounds
    $FileNumber = [Math]::Min($FileNumber, $TotalFiles)

    # Build progress string
    $progressString = "$progressBar] "
    $progressString += "$percentComplete% | "
    $progressString += "Category: $Category | "
    $progressString += "File $FileNumber of $TotalFiles | "
    $progressString += "$fileName"

    # Clear line and write progress
    Write-Host "`r$(' ' * 120)" -NoNewline
    Write-Host "`r$progressString" -NoNewline
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

function Get-VulnerabilitySeverity {
    param (
        [string]$Category,
        [string]$Pattern
    )
    
    switch ($Category) {
        "Weak Manifest Permissions" {
            switch -Regex ($Pattern) {
                'android:debuggable\s*=\s*["\'']true["\'']' { return "Critical" }
                'android\.permission\.(SYSTEM_ALERT_WINDOW|WRITE_SETTINGS|PACKAGE_USAGE_STATS)' { return "High" }
                'android\.permission\.(CAMERA|ACCESS_FINE_LOCATION|READ_CONTACTS)' { return "High" }
                'android:exported\s*=\s*["\'']true["\''][^>]*(?!.*android:permission)' { return "High" }
                'android:protectionLevel\s*=\s*["\'']normal["\'']' { return "Medium" }
                default { return "Medium" }
            }
        }
        "Authentication" { return "High" }
        "API Keys" { return "High" }
        "Component Exports" {
            if ($Pattern -match "android:exported.*true") { return "High" }
            return "Medium"
        }
        "Intent Vulnerabilities" { return "Medium" }
        "SQL Injection" { return "Critical" }
        "Fragment Injection" { return "High" }
        "Permission Issues" {
            if ($Pattern -match "dangerous") { return "High" }
            return "Medium"
        }
        default { return "Low" }
    }
}

function Analyze-AndroidManifest {
    param (
        [string]$ManifestPath,
        [string]$OutputDir
    )
    
    $manifestContent = Get-Content $ManifestPath -Raw
    $manifestReport = @{
        DangerousPermissions = @()
        WeakComponents = @()
        DebugFlags = @()
        ImplicitIntents = @()
        CustomPermissions = @()
    }
    
    function Get-RegexMatches {
        param ($Content, $Pattern)
        $matches = [regex]::Matches($Content, $Pattern)
        return $matches | ForEach-Object { $_.Value }
    }
    
    # Check dangerous permissions
    $dangerousPerms = $patterns['Weak Manifest Permissions'] | 
        Where-Object { $_ -match 'android\.permission\.' } |
        ForEach-Object {
            if ($manifestContent -match $_) {
                $manifestReport.DangerousPermissions += $_
            }
        }
    
    # Check weak components
    $weakComponentPatterns = @(
        '<activity[^>]+android:exported\s*=\s*["\'']true["\''][^>]*>(?!.*android:permission)',
        '<service[^>]+android:exported\s*=\s*["\'']true["\''][^>]*>(?!.*android:permission)',
        '<receiver[^>]+android:exported\s*=\s*["\'']true["\''][^>]*>(?!.*android:permission)',
        '<provider[^>]+android:exported\s*=\s*["\'']true["\''][^>]*>(?!.*android:readPermission)(?!.*android:writePermission)'
    )
    
    foreach ($pattern in $weakComponentPatterns) {
        $matches = Get-RegexMatches -Content $manifestContent -Pattern $pattern
        $manifestReport.WeakComponents += $matches
    }
    
    # Check debug flags
    $debugFlagPatterns = @(
        'android:debuggable\s*=\s*["\'']true["\'']',
        'android:allowBackup\s*=\s*["\'']true["\'']',
        'android:testOnly\s*=\s*["\'']true["\'']'
    )
    
    foreach ($pattern in $debugFlagPatterns) {
        if ($manifestContent -match $pattern) {
            $manifestReport.DebugFlags += $pattern
        }
    }
    
    # Generate report
    $reportContent = @"
Android Manifest Security Analysis
===============================
Scan Date: $(Get-Date)
File: $ManifestPath

1. Dangerous Permission Usage
---------------------------
"@
    
    foreach ($perm in $manifestReport.DangerousPermissions) {
        $reportContent += "`n- $perm"
    }
    
    $reportContent += @"

2. Weakly Protected Components
---------------------------
"@
    
    foreach ($comp in $manifestReport.WeakComponents) {
        $reportContent += "`n- $comp"
    }
    
    $reportContent += @"

3. Debug/Security Flags
--------------------
"@
    
    foreach ($flag in $manifestReport.DebugFlags) {
        $reportContent += "`n- $flag"
    }
    
    $reportContent += @"

Security Recommendations
=====================
1. Permission Hardening:
   - Remove unnecessary dangerous permissions
   - Use fine-grained permissions instead of broad ones
   - Implement runtime permission requests properly

2. Component Security:
   - Add proper permission protection to all exported components
   - Remove android:exported="true" where not needed
   - Use signature or signatureOrSystem protection levels for custom permissions

3. Debug/Security Settings:
   - Ensure android:debuggable is false in production
   - Configure android:allowBackup appropriately
   - Remove android:testOnly flag in production

4. General Security:
   - Implement intent filters with care
   - Use explicit intents where possible
   - Add proper permission checks in exported components
"@
    
    # Save report
    $reportPath = Join-Path $OutputDir "manifest_permission_analysis.txt"
    $reportContent | Set-Content $reportPath
    
    Write-ColorOutput Green "[+] Manifest permission analysis complete"
    Write-ColorOutput Yellow "[*] Found $($manifestReport.DangerousPermissions.Count) dangerous permissions"
    Write-ColorOutput Yellow "[*] Found $($manifestReport.WeakComponents.Count) weakly protected components"
    Write-ColorOutput Yellow "[*] See $reportPath for full analysis"
}

function ConvertTo-SafeHtml {
    param([string]$Text)
    $Text = $Text -replace '&', '&amp;'
    $Text = $Text -replace '<', '&lt;'
    $Text = $Text -replace '>', '&gt;'
    $Text = $Text -replace '"', '&quot;'
    $Text = $Text -replace "'", '&#39;'
    return $Text
}

function Search-Patterns {
    param (
        [string]$ScanDir,
        [string]$SourcePath
    )

    $results = @{}
    $totalFindings = 0
    $lastDisplayTime = [DateTime]::Now
    
    Write-ColorOutput Green "[+] Starting enhanced security scan of Android source..."
    Write-ColorOutput Yellow "[*] Source directory: $SourcePath"
    Write-Host "`n"
    
    # Get all files once at the start
    $allFiles = Get-ChildItem -Path $SourcePath -Recurse -File | 
                Where-Object { $_.Extension -match '\.(xml|java|kt|gradle|properties)$' }
    $totalFiles = $allFiles.Count
    
    foreach ($category in $patterns.Keys) {
        $findings = @()
        $currentFile = 0
        
        foreach ($file in $allFiles) {
            $currentFile++
            
            # Update progress bar only every 100ms to reduce flicker
            $now = [DateTime]::Now
            if (($now - $lastDisplayTime).TotalMilliseconds -ge 100) {
                Write-ProgressBar -Current $currentFile `
                                -Total $totalFiles `
                                -Category $category `
                                -CurrentFile $file.FullName `
                                -FileNumber $currentFile `
                                -TotalFiles $totalFiles
                $lastDisplayTime = $now
            }
            
            foreach ($pattern in $patterns[$category]) {
                try {
                    $matches = Select-String -Path $file.FullName -Pattern $pattern -AllMatches
                    foreach ($match in $matches) {
                        $findings += [PSCustomObject]@{
                            File = $file.FullName.Replace($SourcePath, '')
                            Line = $match.LineNumber
                            Match = $match.Line.Trim()
                            Pattern = $pattern
                            Severity = Get-VulnerabilitySeverity -Category $category -Pattern $pattern
                        }
                    }
                }
                catch {
                    Write-ColorOutput Red "[!] Error scanning file $($file.Name) with pattern: $pattern"
                    continue
                }
            }
        }
        
        if ($findings.Count -gt 0) {
            $results[$category] = $findings
            $totalFindings += $findings.Count
            $categoryFile = Join-Path $ScanDir "$($category.Replace(' ', '_')).csv"
            $findings | Export-Csv -Path $categoryFile -NoTypeInformation
        }
        
        Write-Host "`n" # New line after category completion
    }
    
    # Generate detailed summary report
    $summaryFile = Join-Path $ScanDir "scan_summary.txt"
    
    $summaryContent = @"
Android Security Scan Summary
===========================
Scan Date: $(Get-Date)
Source Path: $SourcePath
Total Findings: $totalFindings

Findings by Category:
-------------------
"@
    
    foreach ($category in $results.Keys) {
        $categoryFindings = $results[$category]
        $severityCounts = $categoryFindings | Group-Object Severity | 
                         Select-Object @{N='Severity';E={$_.Name}}, @{N='Count';E={$_.Count}} |
                         Sort-Object @{Expression={
                             switch($_.Severity) {
                                 'Critical' { 0 }
                                 'High' { 1 }
                                 'Medium' { 2 }
                                 'Low' { 3 }
                                 default { 4 }
                             }
                         }}
        
        $summaryContent += "`n$category ($($categoryFindings.Count) findings):"
        foreach ($severity in $severityCounts) {
            $summaryContent += "`n  - $($severity.Severity): $($severity.Count)"
        }
    }
    
    $summaryContent += @"

Component Security Analysis:
-------------------------
- Exported Components: $($results['Component Exports'].Count) findings
- Intent Vulnerabilities: $($results['Intent Vulnerabilities'].Count) findings
- Permission Issues: $($results['Permission Issues'].Count) findings
- Fragment Injection Risks: $($results['Fragment Injection'].Count) findings
- SQL Injection Vulnerabilities: $($results['SQL Injection'].Count) findings

Critical and High Severity Issues:
------------------------------
"@

    # Add detailed findings for Critical and High severity issues
    foreach ($category in $results.Keys) {
        $criticalAndHighFindings = $results[$category] | Where-Object { $_.Severity -in @('Critical', 'High') }
        if ($criticalAndHighFindings) {
            $summaryContent += "`n$($category):"
            foreach ($finding in $criticalAndHighFindings) {
                $summaryContent += "`n  - [$($finding.Severity)] $($finding.File) (Line: $($finding.Line))"
                $summaryContent += "`n    Pattern: $($finding.Pattern)"
                $summaryContent += "`n    Match: $($finding.Match)"
            }
        }
    }

    $summaryContent += @"

Security Recommendations:
----------------------
1. Component Security:
   - Review and secure all exported components
   - Implement proper permission checks
   - Use explicit intents where possible
   - Validate all input from intents and external sources

2. Permission Management:
   - Remove unused permissions
   - Request permissions at runtime for Android 6.0+
   - Use fine-grained permissions instead of broad ones
   - Implement proper permission checks in components

3. Data Security:
   - Use parameterized queries for all database operations
   - Encrypt sensitive data using strong encryption
   - Avoid storing sensitive data in plaintext
   - Implement proper key management

4. WebView Security:
   - Disable JavaScript if not required
   - Validate all URLs loaded in WebView
   - Avoid loading remote content if possible
   - Implement proper SSL/TLS certificate validation

5. Debug Settings:
   - Remove all debug flags in production
   - Configure proper backup and security settings
   - Remove test code and debug configurations

Note: All findings should be manually verified as they may include false positives.
"@

    $summaryContent | Set-Content $summaryFile

    # Generate HTML report
    $htmlReport = Join-Path $ScanDir "scan_report.html"
    $htmlContent = @"
<!DOCTYPE html>
<html>
<head>
    <title>Android Security Scan Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background-color: #f8f9fa; padding: 20px; margin-bottom: 20px; }
        .critical { color: #dc3545; }
        .high { color: #fd7e14; }
        .medium { color: #ffc107; }
        .low { color: #28a745; }
        .finding { margin-bottom: 10px; padding: 10px; background-color: #f8f9fa; }
        .category { margin-top: 20px; }
        table { width: 100%; border-collapse: collapse; margin-top: 10px; }
        th, td { padding: 8px; text-align: left; border: 1px solid #dee2e6; }
        th { background-color: #e9ecef; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Android Security Scan Report</h1>
        <p>Scan Date: $(Get-Date)</p>
        <p>Source Path: $SourcePath</p>
        <p>Total Findings: $totalFindings</p>
    </div>
"@

    foreach ($category in $results.Keys) {
        $htmlContent += @"
    <div class="category">
        <h2>$category</h2>
        <table>
            <tr>
                <th>Severity</th>
                <th>File</th>
                <th>Line</th>
                <th>Finding</th>
            </tr>
"@
        foreach ($finding in $results[$category]) {
            $severityClass = $finding.Severity.ToLower()
            $htmlContent += @"
            <tr>
                <td class="$severityClass">$(ConvertTo-SafeHtml $finding.Severity)</td>
                <td>$(ConvertTo-SafeHtml $finding.File)</td>
                <td>$($finding.Line)</td>
                <td>$(ConvertTo-SafeHtml $finding.Match)</td>
            </tr>
"@
        }
        $htmlContent += "</table></div>"
    }

    $htmlContent += "</body></html>"
    $htmlContent | Set-Content $htmlReport

    Write-ColorOutput Green "[+] Enhanced scan complete! Results saved to: $ScanDir"
    Write-ColorOutput Yellow "[*] Total findings: $totalFindings"
    Write-ColorOutput Yellow "[*] Review the following files for analysis:"
    Write-ColorOutput Yellow "    - scan_summary.txt: Text-based summary report"
    Write-ColorOutput Yellow "    - scan_report.html: Interactive HTML report"
    Write-ColorOutput Yellow "    - Category-specific CSV files for detailed findings"
}

# Main execution
try {
    $ErrorActionPreference = 'Stop'
    Write-ColorOutput Cyan "[+] Starting Android Security Scanner..."
    
    # Initialize scan directory
    $scanDir = Initialize-ScanEnvironment
    Write-ColorOutput Green "[+] Created scan directory: $scanDir"
    
    # Look for AndroidManifest.xml
    $manifestPath = Get-ChildItem -Path $SourcePath -Recurse -Filter "AndroidManifest.xml" | Select-Object -First 1
    if ($manifestPath) {
        Write-ColorOutput Cyan "[+] Found Android Manifest at: $($manifestPath.FullName)"
        Analyze-AndroidManifest -ManifestPath $manifestPath.FullName -OutputDir $scanDir
    }
    else {
        Write-ColorOutput Yellow "[!] Warning: AndroidManifest.xml not found"
    }
    
    # Perform pattern scanning
    Search-Patterns -ScanDir $scanDir -SourcePath $SourcePath
}
catch {
    Write-ColorOutput Red "[!] Error during scan: $($_.Exception.Message)"
    Write-ColorOutput Red "[!] Stack trace: $($_.ScriptStackTrace)"
    exit 1
}
