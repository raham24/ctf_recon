#!/usr/bin/env python3
"""
CTF Reconnaissance Tool
A comprehensive web application reconnaissance tool designed for CTF competitions
and security assessments.

Author: Security Research
Version: 2.0.0
License: MIT
"""

import requests
import argparse
import socket
import sys
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, urljoin
import re
from threading import Lock
import time
from pathlib import Path

# Constants
VERSION = "2.0.0"
DEFAULT_THREADS = 20
DEFAULT_TIMEOUT = 3
DEFAULT_PORT_RANGE = (20, 1000)
USER_AGENT = "CTF-Recon-Tool/2.0"

# Thread-safe printing
print_lock = Lock()


def safe_print(message):
    """Thread-safe printing function."""
    with print_lock:
        print(message)


def load_wordlist(wordlist_path):
    """
    Load a wordlist from a file.
    
    Args:
        wordlist_path (str): Path to the wordlist file
        
    Returns:
        list: List of words from the file, or empty list if file not found
    """
    if not os.path.exists(wordlist_path):
        safe_print(f"[!] Warning: Wordlist not found: {wordlist_path}")
        return []
    
    try:
        with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
            # Filter out empty lines and comments
            words = [line.strip() for line in f 
                    if line.strip() and not line.strip().startswith('#')]
        return words
    except Exception as e:
        safe_print(f"[!] Error loading wordlist {wordlist_path}: {e}")
        return []


def get_default_wordlist_path(wordlist_name):
    """
    Get the path to a default wordlist file.
    
    Args:
        wordlist_name (str): Name of the wordlist file
        
    Returns:
        str: Full path to the wordlist file
    """
    script_dir = Path(__file__).parent
    wordlist_dir = script_dir / 'wordlists'
    return str(wordlist_dir / wordlist_name)


class CTFRecon:
    """
    Main reconnaissance class for performing various security assessments.
    """
    
    def __init__(self, target_url, port=None, threads=DEFAULT_THREADS, 
                 timeout=DEFAULT_TIMEOUT):
        """
        Initialize the CTFRecon object.
        
        Args:
            target_url (str): Target URL to scan
            port (int, optional): Specific port to use
            threads (int): Number of concurrent threads
            timeout (int): Request timeout in seconds
        """
        self.base_url = target_url.rstrip('/')
        self.port = port
        self.threads = threads
        self.timeout = timeout
        
        # Parse URL components
        parsed = urlparse(self.base_url)
        self.scheme = parsed.scheme
        self.domain = parsed.netloc
        self.path = parsed.path or '/'
        
        # Results storage
        self.found_paths = []
        self.found_params = []
        self.open_ports = []
        self.server_info = {}
        
        # Setup session with headers
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': USER_AGENT,
            'Accept': '*/*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Connection': 'keep-alive'
        })
    
    def response_analyzer(self):
        """
        Analyze the initial response from the target to gather information.
        """
        safe_print("\n[*] Starting Response Analysis...")
        safe_print(f"[*] Target: {self.base_url}")
        
        try:
            response = self.session.get(self.base_url, timeout=self.timeout)
            
            # Basic info
            safe_print(f"[+] Status Code: {response.status_code}")
            safe_print(f"[+] Response Size: {len(response.content)} bytes")
            
            # Server information
            if 'Server' in response.headers:
                self.server_info['server'] = response.headers['Server']
                safe_print(f"[+] Server: {response.headers['Server']}")
            
            if 'X-Powered-By' in response.headers:
                self.server_info['powered_by'] = response.headers['X-Powered-By']
                safe_print(f"[+] Powered By: {response.headers['X-Powered-By']}")
            
            # Security headers analysis
            security_headers = [
                'X-Frame-Options', 'X-XSS-Protection', 
                'X-Content-Type-Options', 'Strict-Transport-Security',
                'Content-Security-Policy'
            ]
            
            missing_headers = [h for h in security_headers if h not in response.headers]
            if missing_headers:
                safe_print(f"[!] Missing Security Headers: {', '.join(missing_headers)}")
            
            # Cookie analysis
            if response.cookies:
                safe_print(f"[+] Cookies Set: {len(response.cookies)}")
                for cookie in response.cookies:
                    flags = []
                    if cookie.secure:
                        flags.append("Secure")
                    if cookie.has_nonstandard_attr('HttpOnly'):
                        flags.append("HttpOnly")
                    safe_print(f"    └─ {cookie.name}: {' '.join(flags) if flags else 'No security flags'}")
            
            # Content analysis
            if response.text:
                # Look for interesting patterns
                patterns = {
                    'emails': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
                    'api_keys': r'[a-zA-Z0-9_-]{32,}',
                    'comments': r'<!--(.*?)-->',
                }
                
                for pattern_name, pattern in patterns.items():
                    matches = re.findall(pattern, response.text, re.DOTALL)
                    if matches:
                        safe_print(f"[+] Found {len(matches)} potential {pattern_name}")
            
        except requests.RequestException as e:
            safe_print(f"[!] Error analyzing response: {e}")
        
        safe_print("[*] Response Analysis Complete")
    
    def directory_brute_force(self, custom_wordlist=None, extensions=None):
        """
        Perform directory and file brute force enumeration.
        
        Args:
            custom_wordlist (list, optional): Custom wordlist to use
            extensions (list, optional): File extensions to test
        """
        safe_print("\n[*] Starting Directory Brute Force...")
        
        # Load wordlist
        if custom_wordlist:
            wordlist = custom_wordlist
        else:
            default_path = get_default_wordlist_path('directories.txt')
            wordlist = load_wordlist(default_path)
            if not wordlist:
                safe_print("[!] No wordlist available. Aborting directory scan.")
                return
        
        # Extend with file extensions if provided
        if extensions:
            wordlist = self._extend_wordlist(wordlist, extensions)
        
        safe_print(f"[*] Testing {len(wordlist)} paths...")
        safe_print(f"[*] Using {self.threads} threads")
        
        def test_path(path):
            url = urljoin(self.base_url, path)
            try:
                response = self.session.get(url, timeout=self.timeout, 
                                           allow_redirects=False)
                
                # Consider 200-299 and 403 as interesting
                if 200 <= response.status_code < 300 or response.status_code == 403:
                    result = f"{url} [{response.status_code}] ({len(response.content)} bytes)"
                    self.found_paths.append(result)
                    safe_print(f"[+] {result}")
                    
                    # Check for interesting response indicators
                    if response.status_code == 403:
                        safe_print(f"    └─ Forbidden - might be interesting!")
                    
                    if 'flag' in response.text.lower() or 'secret' in response.text.lower():
                        safe_print(f"    └─ Contains interesting keywords!")
                
            except requests.RequestException:
                pass
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            executor.map(test_path, wordlist)
        
        safe_print(f"\n[*] Directory Scan Complete. Found {len(self.found_paths)} paths.")
    
    def parameter_fuzzing(self, target_path='/', method='GET', custom_wordlist=None):
        """
        Fuzz for hidden parameters in a given endpoint.
        
        Args:
            target_path (str): Path to fuzz
            method (str): HTTP method to use (GET or POST)
            custom_wordlist (list, optional): Custom parameter wordlist
        """
        safe_print(f"\n[*] Starting Parameter Fuzzing ({method})...")
        
        # Load wordlist
        if custom_wordlist:
            wordlist = custom_wordlist
        else:
            default_path = get_default_wordlist_path('parameters.txt')
            wordlist = load_wordlist(default_path)
            if not wordlist:
                safe_print("[!] No parameter wordlist available. Aborting parameter scan.")
                return
        
        url = urljoin(self.base_url, target_path)
        safe_print(f"[*] Target: {url}")
        safe_print(f"[*] Testing {len(wordlist)} parameters...")
        
        # Get baseline response
        try:
            if method.upper() == 'GET':
                baseline = self.session.get(url, timeout=self.timeout)
            else:
                baseline = self.session.post(url, timeout=self.timeout)
            baseline_length = len(baseline.content)
            baseline_status = baseline.status_code
        except requests.RequestException as e:
            safe_print(f"[!] Error getting baseline: {e}")
            return
        
        def test_parameter(param):
            try:
                if method.upper() == 'GET':
                    response = self.session.get(url, params={param: 'test'}, 
                                               timeout=self.timeout)
                else:
                    response = self.session.post(url, data={param: 'test'}, 
                                                timeout=self.timeout)
                
                # Check for differences from baseline
                length_diff = abs(len(response.content) - baseline_length)
                status_diff = response.status_code != baseline_status
                
                # If there's a significant difference, it might be a valid parameter
                if length_diff > 10 or status_diff:
                    result = f"{param} - Status: {response.status_code}, " \
                            f"Length Diff: {length_diff} bytes"
                    self.found_params.append(result)
                    safe_print(f"[+] Potential parameter: {result}")
                    
                    # Check for errors that might indicate vulnerability
                    error_indicators = ['error', 'exception', 'sql', 'mysql', 
                                      'warning', 'fatal']
                    if any(indicator in response.text.lower() 
                          for indicator in error_indicators):
                        safe_print(f"    └─ Error detected - might be vulnerable!")
                
            except requests.RequestException:
                pass
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            executor.map(test_parameter, wordlist)
        
        safe_print(f"\n[*] Parameter Fuzzing Complete. "
                  f"Found {len(self.found_params)} potential parameters.")
    
    def port_scanner(self, port_range=DEFAULT_PORT_RANGE):
        """
        Scan for open ports on the target host.
        
        Args:
            port_range (tuple): Range of ports to scan (start, end)
        """
        safe_print("\n[*] Starting Port Scan...")
        
        target_host = self.domain.split(':')[0]
        safe_print(f"[*] Target: {target_host}")
        safe_print(f"[*] Scanning ports {port_range[0]}-{port_range[1]}...")
        
        ports = range(port_range[0], port_range[1] + 1)
        
        def scan_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((target_host, port))
                
                if result == 0:
                    self.open_ports.append(port)
                    
                    # Try to grab banner
                    try:
                        sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
                        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                        safe_print(f"[+] Port {port} OPEN - {banner[:100]}")
                    except:
                        safe_print(f"[+] Port {port} OPEN")
                
                sock.close()
            except socket.gaierror:
                safe_print("[!] Hostname could not be resolved")
            except socket.error:
                pass
        
        with ThreadPoolExecutor(max_workers=50) as executor:
            executor.map(scan_port, ports)
        
        safe_print(f"\n[*] Port Scan Complete. "
                  f"Found {len(self.open_ports)} open port(s).")
        return self.open_ports
    
    def subdomain_enum(self, domain=None, custom_wordlist=None):
        """
        Enumerate subdomains for the target domain.
        
        Args:
            domain (str, optional): Domain to enumerate (uses target if not provided)
            custom_wordlist (list, optional): Custom subdomain wordlist
        """
        safe_print("\n[*] Starting Subdomain Enumeration...")
        
        target_domain = domain if domain else self.domain.split(':')[0]
        
        # Load wordlist
        if custom_wordlist:
            wordlist = custom_wordlist
        else:
            default_path = get_default_wordlist_path('subdomains.txt')
            wordlist = load_wordlist(default_path)
            if not wordlist:
                safe_print("[!] No subdomain wordlist available. Aborting subdomain scan.")
                return []
        
        safe_print(f"[*] Target: {target_domain}")
        safe_print(f"[*] Testing {len(wordlist)} subdomains...")
        
        found_subdomains = []
        
        def check_subdomain(sub):
            subdomain = f"{sub}.{target_domain}"
            try:
                # Try DNS resolution
                socket.gethostbyname(subdomain)
                found_subdomains.append(subdomain)
                safe_print(f"[+] Found subdomain: {subdomain}")
                
                # Try HTTP request
                try:
                    r = self.session.get(f"http://{subdomain}", timeout=2)
                    safe_print(f"    └─ HTTP {r.status_code}")
                except:
                    pass
                    
            except socket.gaierror:
                pass
            except Exception:
                pass
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            executor.map(check_subdomain, wordlist)
        
        safe_print(f"\n[*] Subdomain Enumeration Complete. "
                  f"Found {len(found_subdomains)} subdomain(s).")
        return found_subdomains
    
    def _extend_wordlist(self, wordlist, extensions):
        """
        Add file extensions to wordlist entries.
        
        Args:
            wordlist (list): Original wordlist
            extensions (list): Extensions to add
            
        Returns:
            list: Extended wordlist
        """
        extended = list(wordlist)
        for word in wordlist:
            # Don't add extensions to words that already have them
            if not any(word.endswith(ext) for ext in extensions):
                for ext in extensions:
                    extended.append(word + ext)
        return extended
    
    def save_results(self, filename="recon_results.txt"):
        """
        Save all scan results to a file.
        
        Args:
            filename (str): Output filename
        """
        safe_print(f"\n[*] Saving results to {filename}...")
        
        try:
            with open(filename, 'w') as f:
                f.write(f"CTF Reconnaissance Results\n")
                f.write(f"Target: {self.base_url}\n")
                f.write(f"Scan Date: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("=" * 60 + "\n\n")
                
                if self.server_info:
                    f.write("SERVER INFORMATION:\n")
                    f.write("-" * 60 + "\n")
                    for key, value in self.server_info.items():
                        f.write(f"{key}: {value}\n")
                    f.write("\n")
                
                if self.found_paths:
                    f.write("DISCOVERED PATHS:\n")
                    f.write("-" * 60 + "\n")
                    for item in self.found_paths:
                        f.write(f"{item}\n")
                    f.write("\n")
                
                if self.found_params:
                    f.write("DISCOVERED PARAMETERS:\n")
                    f.write("-" * 60 + "\n")
                    for item in self.found_params:
                        f.write(f"{item}\n")
                    f.write("\n")
                
                if self.open_ports:
                    f.write("OPEN PORTS:\n")
                    f.write("-" * 60 + "\n")
                    for port in self.open_ports:
                        f.write(f"{port}\n")
                    f.write("\n")
            
            safe_print(f"[+] Results saved to {filename}")
        except Exception as e:
            safe_print(f"[!] Error saving results: {e}")


def print_banner():
    """Print the tool banner."""
    banner = f"""
    ╔═══════════════════════════════════════╗
    ║   CTF Reconnaissance Tool v{VERSION}     ║
    ║   Web Application Security Scanner    ║
    ╚═══════════════════════════════════════╝
    """
    print(banner)


def main():
    """Main entry point for the tool."""
    print_banner()
    
    parser = argparse.ArgumentParser(
        description='CTF Reconnaissance Tool - Web Application Security Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Basic directory scan:
    %(prog)s -u http://target.com -d
  
  Full reconnaissance:
    %(prog)s -u http://target.com --all
  
  Custom wordlist and output:
    %(prog)s -u http://target.com -d --wordlist custom.txt -o results.txt
  
  Parameter fuzzing with POST:
    %(prog)s -u http://target.com/search.php -f --method POST
        """
    )
    
    # Required arguments
    parser.add_argument('-u', '--url', required=True, 
                       help='Target URL (e.g., http://target.com)')
    
    # Optional arguments
    parser.add_argument('-p', '--port', type=int, 
                       help='Specific port to use')
    parser.add_argument('-t', '--threads', type=int, default=DEFAULT_THREADS, 
                       help=f'Number of threads (default: {DEFAULT_THREADS})')
    parser.add_argument('--timeout', type=int, default=DEFAULT_TIMEOUT, 
                       help=f'Request timeout in seconds (default: {DEFAULT_TIMEOUT})')
    
    # Action flags
    action_group = parser.add_argument_group('scan types')
    action_group.add_argument('-d', '--dir', action='store_true', 
                             help='Directory brute force')
    action_group.add_argument('-f', '--fuzz', action='store_true', 
                             help='Parameter fuzzing')
    action_group.add_argument('-a', '--analyze', action='store_true', 
                             help='Response analysis')
    action_group.add_argument('-s', '--scan', action='store_true', 
                             help='Port scanning')
    action_group.add_argument('-e', '--enum', action='store_true', 
                             help='Subdomain enumeration')
    action_group.add_argument('--all', action='store_true', 
                             help='Run all scans')
    
    # Fuzzing options
    fuzz_group = parser.add_argument_group('fuzzing options')
    fuzz_group.add_argument('--path', default='/', 
                           help='Path for parameter fuzzing (default: /)')
    fuzz_group.add_argument('--method', default='GET', choices=['GET', 'POST'],
                           help='HTTP method for fuzzing (default: GET)')
    
    # Port scan options
    port_group = parser.add_argument_group('port scan options')
    port_group.add_argument('--port-range', 
                           help='Port range to scan (e.g., 1-1000)')
    
    # Output options
    output_group = parser.add_argument_group('output options')
    output_group.add_argument('-o', '--output', 
                             help='Save results to file')
    output_group.add_argument('-v', '--verbose', action='store_true',
                             help='Verbose output')
    
    # Custom wordlists
    wordlist_group = parser.add_argument_group('custom wordlists')
    wordlist_group.add_argument('--wordlist', 
                               help='Custom wordlist file for directory bruteforce')
    wordlist_group.add_argument('--param-list', 
                               help='Custom wordlist file for parameter fuzzing')
    wordlist_group.add_argument('--subdomain-list', 
                               help='Custom wordlist file for subdomain enumeration')
    
    # Extensions
    parser.add_argument('--extensions', 
                       help='File extensions to append (comma-separated, e.g., .php,.html)')
    
    args = parser.parse_args()
    
    # Validate URL
    if not args.url.startswith(('http://', 'https://')):
        print("[!] Error: URL must start with http:// or https://")
        sys.exit(1)
    
    # Initialize recon tool
    try:
        recon = CTFRecon(args.url, args.port, args.threads, args.timeout)
    except Exception as e:
        print(f"[!] Error initializing reconnaissance tool: {e}")
        sys.exit(1)
    
    # Load custom wordlists if provided
    custom_dir_wordlist = None
    custom_param_wordlist = None
    custom_subdomain_wordlist = None
    
    if args.wordlist:
        custom_dir_wordlist = load_wordlist(args.wordlist)
        if custom_dir_wordlist:
            print(f"[+] Loaded {len(custom_dir_wordlist)} entries from {args.wordlist}")
    
    if args.param_list:
        custom_param_wordlist = load_wordlist(args.param_list)
        if custom_param_wordlist:
            print(f"[+] Loaded {len(custom_param_wordlist)} entries from {args.param_list}")
    
    if args.subdomain_list:
        custom_subdomain_wordlist = load_wordlist(args.subdomain_list)
        if custom_subdomain_wordlist:
            print(f"[+] Loaded {len(custom_subdomain_wordlist)} entries from {args.subdomain_list}")
    
    # Parse extensions
    extensions = None
    if args.extensions:
        extensions = [ext.strip() if ext.startswith('.') else f'.{ext.strip()}' 
                     for ext in args.extensions.split(',')]
        print(f"[+] Using extensions: {', '.join(extensions)}")
    
    # Parse port range
    port_range = DEFAULT_PORT_RANGE
    if args.port_range:
        try:
            start, end = map(int, args.port_range.split('-'))
            port_range = (start, end)
        except ValueError:
            print("[!] Invalid port range format. Use: start-end (e.g., 1-1000)")
            sys.exit(1)
    
    # Run selected scans
    start_time = time.time()
    
    try:
        if args.all:
            recon.response_analyzer()
            recon.directory_brute_force(custom_dir_wordlist, extensions)
            recon.parameter_fuzzing(args.path, args.method, custom_param_wordlist)
            recon.port_scanner(port_range)
            recon.subdomain_enum(custom_wordlist=custom_subdomain_wordlist)
        else:
            if args.analyze:
                recon.response_analyzer()
            if args.dir:
                recon.directory_brute_force(custom_dir_wordlist, extensions)
            if args.fuzz:
                recon.parameter_fuzzing(args.path, args.method, custom_param_wordlist)
            if args.scan:
                recon.port_scanner(port_range)
            if args.enum:
                recon.subdomain_enum(custom_wordlist=custom_subdomain_wordlist)
            
            if not any([args.analyze, args.dir, args.fuzz, args.scan, args.enum]):
                print("[!] No action specified. Use -h for help")
                sys.exit(1)
        
        elapsed = time.time() - start_time
        print(f"\n[*] Total scan time: {elapsed:.2f} seconds")
        
        # Save results if requested
        if args.output:
            recon.save_results(args.output)
        
        print("\n[*] Reconnaissance Complete!")
        
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Unexpected error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
