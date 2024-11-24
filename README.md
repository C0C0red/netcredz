# NetCredz

NetCredz is a lightweight, dependency-free tool for extracting cleartext credentials and authentication data from network traffic. Inspired by PCredz, it provides enhanced functionality while maintaining simplicity and efficiency.

# Features

- Parse pcap files or listen on live network interfaces.
- Filter traffic by specific protocols to reduce clutter.
- Support for regex filtering to search for specific patterns or strings.
- Output results to a log file for easy analysis.

# Install

```sh
git clone https://github.com/joey-melo/netcredz.git
```

# Usage

Run with a pcap file:

```sh
python3 netcredz -f capture.pcap
```

Run on a live network interface:

```sh
python3 netcredz -i eth0 
```

## Options

```
options:
  -h, --help            show this help message and exit
  -i INTERFACE, --interface INTERFACE
                        interface
  -f FILE, --file FILE  pcap file path
  -d, --debug           debug mode
  -v, --verbose         verbosity level
  -c FILTERS, --capture-methods FILTERS
                        capture methods
  -r REGEX, --regex REGEX
                        regex string
  -o OUTPUT, --output OUTPUT
                        output log file path (csv)
```

## Supported Protocol

NetCredz supports the following protocols for filtering:

```
ntlm, ldap, http, smtp, snmp, telnet, ftp, kerberos, dhcpv6, llmnr
```

# Future Enhancements

- Implement remote logging to send captured data to a listening server.
