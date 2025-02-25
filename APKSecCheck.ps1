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
        '(\b|\d+)[A-F0-9]{64}(\b|\d+)',
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
        'loadUrl\s*\(\s*"javascript:',
        'extends PreferenceActivity'
    )
    "SQL Injection" = @(
        'db\.rawQuery\s*\(',
        'db\.execSQL\s*\(',
        'SQLiteDatabase\.rawQuery\s*\(',
        'getReadableDatabase\(\)',
        'getWritableDatabase\(\)',
        'openOrCreateDatabase'
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
        'com\.ramdroid\.appquarantine',
        '/system/bin/su',
        '/system/xbin/su',
        '/sbin/su',
        'supersu',
        'superuser'
    )
    "Insecure SSL/TLS Configuration" = @(
        'HttpsURLConnection\.setDefaultHostnameVerifier\(null\)',
        'Cipher\.getInstance\(\s*[''"](?:DES|DESede)(?:/\w+)*[''"]',
        'SSLContext\.getInstance\(\s*[''"]SSL[''"]',
        'SSLContext\.getInstance\(\s*[''"]TLS[''"]',
        'SSLContext\.getInstance\(\s*[''"]TLSv1[''"]',
        'SSLContext\.getInstance\(\s*[''"]TLSv1\.1[''"]',
        'ALLOW_ALL_HOSTNAME_VERIFIER',
        'AllowAllHostnameVerifier',
        'setHostnameVerifier\s*\(\s*[^)]*ALLOW_ALL',
        'X509TrustManager\s*\{[^\}]*return\s+null',
        'X509TrustManager\s*\{[^\}]*return\s+true'
    )
    # New categories from first file (paste.txt)
    "Data Storage" = @(
        # Shared Preferences
        'getSharedPreferences\s*\(',
        'SharedPreferences\.Editor',
        'edit\(\)\.putString',
        'MODE_WORLD_READABLE',
        'MODE_WORLD_WRITEABLE',
        
        # SQLite Database (some already in SQL Injection)
        'openOrCreateDatabase',
        'execSQL',
        'rawQuery',
        
        # Firebase Database
        '\.firebaseio\.com',
        'FirebaseDatabase\.getInstance',
        
        # Realm Database
        'RealmConfiguration',
        'Realm\.getInstance',
        
        # Internal/External Storage
        'openFileOutput',
        'FileInputStream',
        'getExternalFilesDir',
        'getExternalFilesDirs',
        'getExternalCacheDir', 
        'getExternalCacheDirs',
        'getCacheDir',
        'getExternalStorageState',
        'getExternalStorageDirectory',
        'getExternalStoragePublicDirectory',
        
        # Temporary Files
        'createTempFile\s*\(',
        'File\.createTempFile'
    )
    "Logging and Information Disclosure" = @(
        # Various logging mechanisms
        'Log\.v\s*\(',
        'Log\.d\s*\(',
        'Log\.i\s*\(',
        'Log\.w\s*\(',
        'Log\.e\s*\(',
        'logger\.log\s*\(',
        'logger\.logp\s*\(',
        'log\.info',
        'System\.out\.print',
        'System\.err\.print',
        'printStackTrace\s*\(',
        
        # Push Notifications
        'NotificationManager',
        'setContentTitle\s*\(',
        'setContentText\s*\(',
        
        # Screenshots & UI
        'FLAG_SECURE',
        'inputType\s*=\s*[''"]textPassword[''"]',
        'textAutoComplete',
        'textAutoCorrect',
        'textNoSuggestions'
    )
    "Memory Management" = @(
        # Memory related
        '\.flush\s*\(',
        'ClipboardManager',
        'setPrimaryClip\s*\(',
        'OnPrimaryClipChangedListener'
    )
    "Hardcoded Sensitive Information" = @(
        # Various hardcoded patterns
        'String (password|key|token|username|url|database|secret|bearer) = "',
        '_key"|_secret"|_token"|_client_id"|_api"|_debug"|_prod"|_stage"'
    )
    "Cryptography" = @(
        # Crypto related
        'SecretKeySpec\s*\(',
        'IvParameterSpec\s*\(',
        'Signature\.getInstance\s*\(',
        'MessageDigest\.getInstance\s*\(',
        'Mac\.getInstance\s*\(',
        'Cipher\.getInstance\s*\(',
        # Weak ciphers
        'Cipher\.getInstance\s*\([''"][^''"]*/ECB/[^''"]*[''"]',
        'Cipher\.getInstance\s*\([''"][^''"]*/CBC/[^''"]*[''"]',
        'Cipher\.getInstance\s*\([''"][^''"]*/None/[^''"]*[''"]',
        'Cipher\.getInstance\s*\([''"]DES[^''"]*[''"]',
        'Cipher\.getInstance\s*\([''"]AES[^''"]*[''"]',
        'Cipher\.getInstance\s*\([''"]RC4[^''"]*[''"]',
        'PKCS1Padding',
        # Random
        'new Random\s*\(',
        'SHA1PRNG',
        'Dual_EC_DRBG'
    )
    "Biometric Authentication" = @(
        'BiometricPrompt',
        'BiometricManager',
        'FingerprintManager',
        'CryptoObject',
        'setInvalidatedByBiometricEnrollment'
    )
    "Network Security" = @(
        # Network Security Config
        'android:networkSecurityConfig',
        'network_security_config\.xml',
        
        # MITM and HTTP
        'HttpURLConnection\)',
        'SSLCertificateSocketFactory\.getInsecure',
        
        # Certificate verification
        'X509Certificate',
        'checkServerTrusted\s*\(',
        'checkClientTrusted\s*\(',
        'getAcceptedIssuers\s*\(',
        'onReceivedSslError',
        'sslErrorHandler',
        '\.proceed\s*\(',
        
        # Certificate pinning
        '<pin-set',
        '<pin digest',
        'certificatePinner',
        'trustManagerFactory',
        
        # Security provider
        'ProviderInstaller\.installIfNeeded',
        'ProviderInstaller\.installIfNeededAsync'
    )
    "Component Security" = @(
        # Permissions
        'checkCallingOrSelfPermission',
        'checkSelfPermission',
        
        # XSS and Code execution
        '\.evaluateJavascript\s*\(',
        '\.loadUrl\s*\("javascript:',
        'Runtime\.getRuntime\(\)\.exec\s*\(',
        
        # WebView settings
        'setAllowFileAccess\s*\(',
        'setAllowFileAccessFromFileURLs\s*\(',
        'setAllowUniversalAccessFromFileURLs\s*\(',
        'setAllowContentAccess\s*\(',
        'setWebContentsDebuggingEnabled\s*\(',
        'addJavascriptInterface\s*\(',
        
        # URL handling
        'shouldOverrideUrlLoading\s*\(',
        'shouldInterceptRequest\s*\(',
        
        # Serialization
        'getSerializable\s*\(',
        'getSerializableExtra\s*\(',
        'new Gson\(\)'
    )
    "WebView Cleanup" = @(
        '\.clearCache\s*\(',
        '\.deleteAllData\s*\(',
        '\.removeAllCookies\s*\(',
        '\.deleteRecursively\s*\(',
        '\.clearFormData\s*\('
    )
    "Application Management" = @(
        'AppUpdateManager',
        'application/vnd\.android\.package-archive',
        'setDataAndType\s*\(',
        'installApp\s*\('
    )
    "Development and Debugging" = @(
        'StrictMode\.setThreadPolicy',
        'StrictMode\.setVmPolicy',
        'RuntimeException\s*\(',
        'UncaughtExceptionHandler\s*\(',
        'isDebuggable',
        'isDebuggerConnected'
    )
    "Obfuscation Detection" = @(
        'package\s+[a-z](\.[a-z0-9]){2,}',
        '(?:class|interface)\s+[a-z](?:\$[a-z0-9]){1,}(?!\w)',
        '(?:class|interface)\s+[a-z]{1,2}(?![a-zA-Z])',
        '(?:class|interface)\s+([a-z])\1+(?!\w)',
        'void\s+[a-z](?:\$[a-z0-9])*\s*\(',  
        '(?:public|private|protected)\s+[a-z](?:\$[a-z0-9])*\s*\(',
        '(?:String|int|boolean|void)\s+[a-z][0-9]+(?:\s*=|\s*;)',
        '(?:abstract|final)\s+class\s+[a-z]{1,2}[0-9]*(?!\w)',
        '(?:[a-z]{1,2}\.){3,}[a-z]{1,2}\s*\(',
        'import\s+[a-z](\.[a-z0-9]){2,}\*',
        'import\s+static\s+[a-z](\.[a-z0-9]){2,}[^.]*',
        '(?:class|interface)\s+[a-zA-Z]{2,3}(?:[0-9]+[a-zA-Z]|[a-zA-Z]+[0-9])+(?!\w)',
        '(?:class|interface)\s+[a-z](?!\w)(?<!Map)(?<!Set)(?<!Id)(?<!Io)',
        '\$\$[a-zA-Z]+\$[0-9]+',
        '\$[a-zA-Z]+\$[a-zA-Z0-9]+(?<!Builder)(?<!Factory)(?<!Helper)'
    )
    "Security Detection Mechanisms" = @(
        # Anti-debugging
        'isDebuggable',
        'isDebuggerConnected',
        
        # Integrity checks
        '\.getEntry\s*\("classes',
        
        # Emulator detection
        'Build\.MODEL\.contains\s*\(',
        'Build\.MANUFACTURER\.contains\s*\(',
        'Build\.HARDWARE\.contains\s*\(',
        'Build\.PRODUCT\.contains\s*\(',
        '/genyd',
        
        # Defence mechanisms
        'SafetyNetClient'
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
                'android:debuggable\s*=\s*[`"`'']true[`"`'']' { return "Critical" }
                'android\.permission\.(SYSTEM_ALERT_WINDOW|WRITE_SETTINGS|PACKAGE_USAGE_STATS)' { return "High" }
                'android\.permission\.(CAMERA|ACCESS_FINE_LOCATION|READ_CONTACTS)' { return "High" }
                'android:exported\s*=\s*[`"`'']true[`"`''][^>]*(?!.*android:permission)' { return "High" }
                'android:protectionLevel\s*=\s*[`"`'']normal[`"`'']' { return "Medium" }
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
        # New categories and severity assignments
        "Sensitive Data" {
            switch -Regex ($Pattern) {
                '-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----' { return "Critical" }
                '-----BEGIN\s+(?:DSA\s+)?PRIVATE\s+KEY-----' { return "Critical" }
                '-----BEGIN\s+(?:EC\s+)?PRIVATE\s+KEY-----' { return "Critical" }
                '-----BEGIN\s+OPENSSH\s+PRIVATE\s+KEY-----' { return "Critical" }
                '-----BEGIN\s+PGP\s+PRIVATE\s+KEY\s+BLOCK-----' { return "Critical" }
                '\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b' { return "Medium" }
                default { return "High" }
            }
        }
        "URLs & Endpoints" { return "Low" }
        "IP Addresses" {
            if ($Pattern -match "localhost|\b127\.0\.0\.1\b") { return "Low" }
            return "Medium"
        }
        "Intent and WebView" {
            switch -Regex ($Pattern) {
                'webview\s*\.setJavaScriptEnabled\s*=\s*true' { return "High" }
                'webview\s*\.addJavascriptInterface\s*\(' { return "High" }
                default { return "Medium" }
            }
        }
        "Provider" {
            if ($Pattern -match "ContentProvider\.(query|insert|update|delete)") { return "High" }
            return "Medium"
        }
        "Insecure Root Check" { return "Medium" }
        "Insecure SSL/TLS Configuration" {
            switch -Regex ($Pattern) {
                'ALLOW_ALL_HOSTNAME_VERIFIER' { return "Critical" }
                'AllowAllHostnameVerifier' { return "Critical" }
                'setHostnameVerifier\s*\(\s*[^)]*ALLOW_ALL' { return "Critical" }
                'X509TrustManager\s*\{[^\}]*return\s+(null|true)' { return "Critical" }
                'SSLContext\.getInstance\(\s*[`"`'']SSL[`"`'']' { return "High" }
                'SSLContext\.getInstance\(\s*[`"`'']TLS[`"`'']' { return "Medium" }
                'SSLContext\.getInstance\(\s*[`"`'']TLSv1[`"`'']' { return "High" }
                'SSLContext\.getInstance\(\s*[`"`'']TLSv1\.1[`"`'']' { return "Medium" }
                'Cipher\.getInstance\(\s*[`"`''](?:DES|DESede)' { return "High" }
                default { return "High" }
            }
        }
        "Data Storage" {
            switch -Regex ($Pattern) {
                'MODE_WORLD_READABLE' { return "High" }
                'MODE_WORLD_WRITEABLE' { return "High" }
                'getExternalStorageDirectory' { return "Medium" }
                'getExternalStoragePublicDirectory' { return "Medium" }
                'FirebaseDatabase\.getInstance' { return "Medium" }
                default { return "Low" }
            }
        }
        "Logging and Information Disclosure" {
            switch -Regex ($Pattern) {
                'Log\.(v|d|i|w|e)\s*\(' { return "Medium" }
                'System\.(out|err)\.print' { return "Medium" }
                'printStackTrace\s*\(' { return "Medium" }
                'FLAG_SECURE' { return "Low" }
                'inputType\s*=\s*[`"`'']textPassword[`"`'']' { return "Low" }
                default { return "Low" }
            }
        }
        "Memory Management" {
            if ($Pattern -match "ClipboardManager|setPrimaryClip") { return "Medium" }
            return "Low"
        }
        "Hardcoded Sensitive Information" { return "High" }
        "Cryptography" {
            switch -Regex ($Pattern) {
                'Cipher\.getInstance\s*\([`"`''].*?/ECB/' { return "Critical" }
                'Cipher\.getInstance\s*\([`"`'']DES' { return "Critical" }
                'Cipher\.getInstance\s*\([`"`'']RC4' { return "High" }
                'new Random\s*\(' { return "Medium" }
                'SHA1PRNG' { return "Medium" }
                'Dual_EC_DRBG' { return "High" }
                default { return "Medium" }
            }
        }
        "Biometric Authentication" { return "Low" }
        "Network Security" {
            switch -Regex ($Pattern) {
                'SSLCertificateSocketFactory\.getInsecure' { return "Critical" }
                'onReceivedSslError.*\.proceed\s*\(' { return "Critical" }
                'HttpURLConnection\)' { return "Medium" }
                'checkServerTrusted\s*\(' { return "Medium" }
                '<pin-set' { return "Low" }
                'certificatePinner' { return "Low" }
                'ProviderInstaller' { return "Low" }
                default { return "Medium" }
            }
        }
        "Component Security" {
            switch -Regex ($Pattern) {
                '\.evaluateJavascript\s*\(' { return "High" }
                '\.loadUrl\s*\([`"`'']javascript:' { return "High" }
                'Runtime\.getRuntime\(\)\.exec\s*\(' { return "Critical" }
                'setAllowFileAccess\s*\(' { return "Medium" }
                'setAllowFileAccessFromFileURLs\s*\(' { return "High" }
                'setAllowUniversalAccessFromFileURLs\s*\(' { return "High" }
                'setWebContentsDebuggingEnabled\s*\(' { return "Medium" }
                'addJavascriptInterface\s*\(' { return "High" }
                'getSerializable' { return "Medium" }
                'new Gson\(\)' { return "Low" }
                'checkCallingOrSelfPermission' { return "Low" }
                'checkSelfPermission' { return "Low" }
                default { return "Medium" }
            }
        }
        "WebView Cleanup" { return "Low" }
        "Application Management" {
            if ($Pattern -match "application/vnd\.android\.package-archive") { return "Medium" }
            if ($Pattern -match "installApp\s*\(") { return "Medium" }
            return "Low"
        }
        "Development and Debugging" {
            if ($Pattern -match "isDebuggable|isDebuggerConnected") { return "Medium" }
            return "Low"
        }
        "Obfuscation Detection" { return "Low" }
        "Security Detection Mechanisms" {
            switch -Regex ($Pattern) {
                'isDebuggable|isDebuggerConnected' { return "Low" }
                '\.getEntry\s*\([`"`'']classes' { return "Low" }
                'SafetyNetClient' { return "Low" }
                default { return "Low" }
            }
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
