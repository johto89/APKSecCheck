# APKSecCheck

APKSecCheck is a security scanner designed to analyze Android APK files by disassembling the source code and scanning it for common security vulnerabilities. This tool is intended for security researchers, penetration testers, and developers who wish to audit their APK source code for sensitive data leaks, insecure configurations, and other security flaws before deploying the app.

---

## 🛠️ Features

- **Pattern Matching**: Scans the APK source code for various sensitive patterns, such as:
  - API Keys and Secrets
  - URLs and Endpoints
  - Authentication Credentials
  - IP Addresses (including private and local network addresses)
  - Database Connection Strings
  - AWS Keys
  - Sensitive Data (Email, MD5, SHA1, SHA256 hashes)
  - Certificates & Keys
  - And more...

- **Output Reports**: Generates detailed reports with:
  - Summary of total findings.
  - CSV files for each category with specific details about the matches.
  - A scan summary in a text file for quick overview.



---

## 🚀 How to Use

1. **Prerequisites**:
    - PowerShell version 5.0 or later
    - A source directory containing the decompiled APK source code

2. **Clone this repository**:
    ```bash
    git clone https://github.com/yourusername/APKSecCheck.git
    cd APKSecCheck
    ```

3. **Run the script**:
    ```powershell
    .\APKSecCheck.ps1 -SourcePath "path_to_decompiled_apk_source"
    ```

   The `SourcePath` parameter is mandatory and should point to the directory containing the decompiled APK source code (e.g., using tools like JADX or APKTool).

   Optionally, you can specify the `OutputPath` parameter to define where the scan results will be stored (default is `.\scan_results`).

   Example:
    ```powershell
    .\APKSecCheck.ps1 -SourcePath "C:\APK\DecompiledSource" -OutputPath "C:\ScanResults"
    ```

4. **View Results**:
   After the scan completes, the tool will generate the following:
   - A directory named `scan_yyyyMMdd_HHmmss` containing:
     - Category-specific CSV files (e.g., `API_Keys.csv`, `URLs_Endpoints.csv`, etc.)
     - A summary text file (`scan_summary.txt`) with an overview of findings.
     
---

## 📊 Example Output

After running the scan, you will receive results such as:

- **scan_summary.txt**: A summary report of total findings by category.
- **Category CSVs**: Detailed findings for each category, listing the files, line numbers, and matching patterns found in the source code.

---

## 📜 Disclaimer

APKSecCheck is a security analysis tool designed to help identify potential vulnerabilities in Android APK source code. While it provides a useful assessment, **it is not guaranteed to catch all vulnerabilities**. The patterns used for scanning may produce **false positives** and **false negatives**, so it is essential to manually verify all findings.

By using this tool, you agree to the following:
- You are solely responsible for the ethical use of this tool and should only run it against APK files you own or have explicit permission to scan.
- The author is not liable for any consequences that arise from the use or misuse of this tool.

---

## 🛡️ Contributing

If you would like to contribute to APKSecCheck, feel free to fork the repository and submit a pull request. All contributions are welcome!

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
