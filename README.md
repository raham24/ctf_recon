# CTF Reconnaissance Tool

A comprehensive web application reconnaissance tool designed for Capture The Flag (CTF) competitions and security assessments. This tool automates the discovery of hidden directories, parameters, subdomains, and open ports on target web applications.

## Features

### Core Functionality
- **Directory and File Discovery**: Brute force enumeration of directories and files using extensive wordlists
- **Parameter Fuzzing**: Identify hidden GET/POST parameters that may be vulnerable to injection attacks
- **Subdomain Enumeration**: Discover subdomains through DNS resolution and HTTP probing
- **Port Scanning**: Identify open ports and attempt banner grabbing for service identification
- **Response Analysis**: Analyze HTTP responses for security headers, cookies, and information disclosure

### Advanced Features
- **Multi-threaded Scanning**: Configurable thread count for optimal performance
- **Custom Wordlists**: Support for user-provided wordlists for all scan types
- **File Extension Support**: Automatically append common file extensions during directory enumeration
- **Comprehensive Reporting**: Save detailed scan results to text files
- **Error Detection**: Identify potential vulnerabilities through error message analysis
- **Session Management**: Maintains persistent sessions for authenticated testing

## Installation

### Prerequisites
- Python 3.6 or higher
- pip package manager

### Clone Repository
```bash
git clone https://github.com/yourusername/ctf-recon-tool.git
cd ctf-recon-tool
```

### Install Dependencies
```bash
pip install -r requirements.txt
```

Alternatively, install dependencies manually:
```bash
pip install requests
```

## Usage

### Basic Usage

Display help information:
```bash
python3 ctf_recon.py -h
```

### Scan Types

#### Directory Enumeration
Discover hidden directories and files:
```bash
python3 ctf_recon.py -u http://target.com -d
```

With custom wordlist and file extensions:
```bash
python3 ctf_recon.py -u http://target.com -d --wordlist custom_dirs.txt --extensions .php,.html,.txt
```

#### Parameter Fuzzing
Test for hidden parameters using GET requests:
```bash
python3 ctf_recon.py -u http://target.com/search.php -f
```

Test specific endpoint with POST method:
```bash
python3 ctf_recon.py -u http://target.com/login.php -f --path /login.php --method POST
```

#### Response Analysis
Analyze target response for security information:
```bash
python3 ctf_recon.py -u http://target.com -a
```

#### Port Scanning
Scan for open ports:
```bash
python3 ctf_recon.py -u http://target.com -s
```

Custom port range:
```bash
python3 ctf_recon.py -u http://target.com -s --port-range 1-65535
```

#### Subdomain Enumeration
Discover subdomains:
```bash
python3 ctf_recon.py -u http://target.com -e
```

#### Comprehensive Scan
Run all scan types:
```bash
python3 ctf_recon.py -u http://target.com --all
```

### Advanced Options

#### Threading
Adjust the number of concurrent threads (default: 20):
```bash
python3 ctf_recon.py -u http://target.com -d -t 50
```

#### Timeout
Set request timeout in seconds (default: 3):
```bash
python3 ctf_recon.py -u http://target.com -d --timeout 5
```

#### Output to File
Save results to a file:
```bash
python3 ctf_recon.py -u http://target.com --all -o results.txt
```

#### Verbose Output
Enable verbose error messages:
```bash
python3 ctf_recon.py -u http://target.com -d -v
```

### Complete Example
```bash
python3 ctf_recon.py -u http://target.com \
    -d -f -a -s -e \
    -t 30 \
    --timeout 5 \
    --extensions .php,.html \
    --port-range 1-1000 \
    -o full_scan_results.txt
```

## Wordlists

The tool includes three comprehensive wordlists located in the `wordlists/` directory:

### directories.txt
Contains over 600 entries covering:
- Admin panels and control interfaces
- Common CMS paths (WordPress, Drupal, Joomla)
- Configuration and backup files
- API endpoints
- Version control artifacts
- Server configuration files
- Development and testing paths
- Flag-specific entries for CTF competitions

### parameters.txt
Contains over 400 parameter names including:
- Common injection points
- File operation parameters
- Command execution vectors
- Authentication parameters
- API-related parameters
- Database operation parameters
- CTF-specific flag parameters

### subdomains.txt
Contains over 350 common subdomains:
- Service subdomains (www, mail, ftp, api)
- Development environments (dev, staging, test)
- Infrastructure components (cdn, proxy, gateway)
- Regional variants
- Common service names

## Command Line Arguments

### Required
- `-u, --url URL`: Target URL (must include http:// or https://)

### Scan Types
- `-d, --dir`: Directory brute force
- `-f, --fuzz`: Parameter fuzzing
- `-a, --analyze`: Response analysis
- `-s, --scan`: Port scanning
- `-e, --enum`: Subdomain enumeration
- `--all`: Run all scan types

### Configuration
- `-t, --threads NUM`: Number of threads (default: 20)
- `--timeout SEC`: Request timeout in seconds (default: 3)
- `-p, --port NUM`: Specific port to use

### Fuzzing Options
- `--path PATH`: Path for parameter fuzzing (default: /)
- `--method METHOD`: HTTP method for fuzzing (GET or POST, default: GET)

### Port Scan Options
- `--port-range RANGE`: Port range to scan (e.g., 1-1000)

### Custom Wordlists
- `--wordlist FILE`: Custom wordlist for directory brute force
- `--param-list FILE`: Custom wordlist for parameter fuzzing
- `--subdomain-list FILE`: Custom wordlist for subdomain enumeration

### File Extensions
- `--extensions EXT`: Comma-separated list of extensions (e.g., .php,.html,.txt)

### Output
- `-o, --output FILE`: Save results to file
- `-v, --verbose`: Verbose output with detailed error messages

## Output Format

Results are displayed in real-time during scanning and can be saved to a file using the `-o` option. The output file contains:

1. **Server Information**: Server type, powered-by headers, security header analysis
2. **Discovered Paths**: All found directories and files with status codes and sizes
3. **Discovered Parameters**: Potential parameters with response differences
4. **Open Ports**: List of open ports discovered during port scanning
5. **Subdomains**: Successfully resolved subdomains with HTTP status codes

## Security Considerations

### Responsible Use
This tool is designed for authorized security testing and CTF competitions only. Users must:
- Only test systems they own or have explicit permission to test
- Comply with all applicable laws and regulations
- Follow responsible disclosure practices for any vulnerabilities discovered
- Respect rate limiting and avoid causing denial of service

### Legal Notice
Unauthorized access to computer systems is illegal. The authors assume no liability for misuse of this tool.

## Performance Tuning

### Threading
- Default: 20 threads provides good balance
- Low-bandwidth: Reduce to 5-10 threads
- High-bandwidth: Increase to 50-100 threads
- Be cautious with very high thread counts to avoid overwhelming targets

### Timeout
- Fast networks: 2-3 seconds
- Slow networks: 5-10 seconds
- Unstable connections: 10+ seconds

### Wordlist Optimization
- Start with smaller, targeted wordlists
- Use custom wordlists based on reconnaissance findings
- Combine multiple passes with different wordlists

## Troubleshooting

### Connection Issues
**Problem**: Timeout errors or connection refused
**Solution**: 
- Verify target URL is correct and accessible
- Increase timeout value with `--timeout`
- Check firewall rules and network connectivity
- Reduce thread count if overwhelming target

### Wordlist Not Found
**Problem**: "Wordlist not found" warnings
**Solution**:
- Ensure wordlists directory exists in the same folder as the script
- Verify wordlist files exist: directories.txt, parameters.txt, subdomains.txt
- Use absolute paths for custom wordlists

### No Results Found
**Problem**: Scan completes but finds nothing
**Solution**:
- Verify target is responding correctly
- Try different wordlists
- Add file extensions with `--extensions`
- Check if target requires authentication
- Increase timeout for slow responses

### Rate Limiting
**Problem**: Getting blocked or rate limited
**Solution**:
- Reduce thread count with `-t`
- Increase timeout between requests
- Use proxy or VPN if appropriate
- Contact system owner for whitelisting

## Contributing

Contributions are welcome! Please follow these guidelines:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/improvement`)
3. Commit your changes (`git commit -am 'Add new feature'`)
4. Push to the branch (`git push origin feature/improvement`)
5. Create a Pull Request

### Areas for Contribution
- Additional wordlist entries
- New scan types and modules
- Performance optimizations
- Bug fixes and error handling
- Documentation improvements
- Unit tests

## Changelog

### Version 2.0.0 (Current)
- Complete codebase refactor for improved maintainability
- Separated wordlists into external files
- Enhanced error handling and logging
- Added support for custom wordlists
- Improved multi-threading performance
- Added file extension support
- Enhanced parameter fuzzing with POST support
- Added verbose mode for debugging
- Improved documentation and help text

### Version 1.0.0
- Initial release
- Basic directory enumeration
- Parameter fuzzing
- Port scanning
- Subdomain enumeration

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Inspired by tools like dirb, dirbuster, gobuster, and ffuf
- Wordlists curated from multiple open-source security projects
- Built for the CTF and security research community

## Author

Security Research Team

## Contact

For questions, suggestions, or security concerns:
- GitHub Issues: https://github.com/yourusername/ctf-recon-tool/issues
- Email: security@example.com

## Disclaimer

This tool is provided for educational and authorized testing purposes only. The authors and contributors are not responsible for any misuse or damage caused by this tool. Always ensure you have proper authorization before testing any systems.

---

**Note**: This tool is designed specifically for CTF competitions and authorized security assessments. Always follow ethical hacking guidelines and obtain proper authorization before testing any systems you do not own.
