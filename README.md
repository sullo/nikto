nikto
=====
[![alt text](https://cirt.net/wp-content/uploads/2025/12/patreon.png "Become a patron of Nikto!")](https://www.patreon.com/sullo)


Nikto web server scanner  - https://cirt.net/Nikto2 

Full documentation - https://github.com/sullo/nikto/wiki

Run normally:

~~~
git clone https://github.com/sullo/nikto
# Main script is in program/
cd nikto/program
# Run using the shebang interpreter
./nikto.pl -h http://www.example.com
# Run using perl (if you forget to chmod)
perl nikto.pl -h http://www.example.com
~~~

Run as a Docker container from ghcr.io:
`docker pull ghcr.io/sullo/nikto:latest`

Run as a Docker container from Dockerfile:

~~~bash
git clone https://github.com/sullo/nikto.git
cd nikto
docker build -t sullo/nikto .
# Call it without arguments to display the full help
docker run --rm sullo/nikto
# Basic usage
docker run --rm sullo/nikto -h http://www.example.com
# To save the report in a specific format, mount /tmp as a volume:
docker run --rm -v $(pwd):/tmp sullo/nikto -h http://www.example.com -o /tmp/out.json
~~~

Basic usage:

```
   Options:
       -Add-header         Add HTTP headers (can be used multiple times, one per header pair)
       -ask+               Whether to ask about submitting updates
                               yes   Ask about each (default)
                               no    Don't ask, don't send
                               auto  Don't ask, just send
       -check6             Check if IPv6 is working (connects to ipv6.google.com or value set in nikto.conf)
       -Cgidirs+           Scan these CGI dirs: "none", "all", or values like "/cgi/ /cgi-a/"
       -config+            Use this config file
       -Display+           Turn on/off display outputs:
                               1     Show redirects
                               2     Show cookies received
                               3     Show all 200/OK responses
                               4     Show URLs which require authentication
                               D     Debug output
                               E     Display all HTTP errors
                               P     Print progress to STDOUT
                               S     Scrub output of IPs and hostnames
                               V     Verbose output
       -dbcheck           Check database and other key files for syntax errors
       -evasion+          Encoding technique:
                               1     Random URI encoding (non-UTF8)
                               2     Directory self-reference (/./)
                               3     Premature URL ending
                               4     Prepend long random string
                               5     Fake parameter
                               6     TAB as request spacer
                               7     Change the case of the URL
                               8     Use Windows directory separator (\)
                               A     Use a carriage return (0x0d) as a request spacer
                               B     Use binary value 0x0b as a request spacer
        -followredirects   Follow 3xx redirects to new location
        -Format+           Save file (-o) format. Can specify multiple formats separated by commas (e.g., htm,sql,txt,json,xml):
                               csv   Comma-separated-value
                               json  JSON Format
                               htm   HTML Format
                               sql   Generic SQL (see docs for schema)
                               sqld  SQL Direct (directly inserts into MySQL/PostgreSQL database)
                               txt   Plain text
                               xml   XML Format
                               (if not specified the format will be taken from the file extension passed to -output)
                               Note: sqld format requires DB_TYPE, DB_HOST, DB_PORT, DB_NAME in nikto.conf
                                     and NIKTO_DB_USER, NIKTO_DB_PASS environment variables
       -Help              This help information
       -host+             Target host/URL
       -id+               Host authentication to use, format is id:pass or id:pass:realm
       -ipv4              IPv4 Only
       -ipv6              IPv6 Only
       -key+              Client certificate key file
       -list-plugins      List all available plugins, perform no testing
       -maxtime+          Maximum testing time per host (e.g., 1h, 60m, 3600s)
       -mutate+           Guess additional file names:
                               1     Test all files with all root directories
                               2     Guess for password file names
                               3     Enumerate user names via Apache (/~user type requests)
                               4     Enumerate user names via cgiwrap (/cgi-bin/cgiwrap/~user type requests)
                               5     Attempt to brute force sub-domain names, assume that the host name is the parent domain
                               6     Attempt to guess directory names from the supplied dictionary file
       -mutate-options    Provide information for mutates
       -nocheck           Don't check for updates on startup
       -nocookies         Do not use cookies from responses in requests (cookies are stored and sent by default)
       -nointeractive     Disables interactive features
       -nolookup          Disables DNS lookups
       -noslash           Strip trailing slash from URL (e.g., '/admin/' to '/admin')
       -nossl             Disables the use of SSL
       -no404             Disables nikto attempting to guess a 404 page
       -Option            Over-ride an option in nikto.conf, can be issued multiple times
       -output+           Write output to this file ('.' for auto-name)
       -Pause+            Pause between tests (seconds)
       -Platform+         Platform of target (nix, win, all)
       -Plugins+          List of plugins to run (default: ALL)
       -port+             Port to use (default 80)
       -RSAcert+          Client certificate file
       -root+             Prepend root value to all requests, format is /directory
       -Save              Save positive responses to this directory ('.' for auto-name)
       -ssl               Force ssl mode on port
       -Tuning+           Scan tuning:
                               1     Interesting File / Seen in logs
                               2     Misconfiguration / Default File
                               3     Information Disclosure
                               4     Injection (XSS/Script/HTML)
                               5     Remote File Retrieval - Inside Web Root
                               6     Denial of Service
                               7     Remote File Retrieval - Server Wide
                               8     Command Execution / Remote Shell
                               9     SQL Injection
                               0     File Upload
                               a     Authentication Bypass
                               b     Software Identification
                               c     Remote Source Inclusion
                               d     WebService
                               e     Administrative Console
                               x     Reverse Tuning Options (i.e., include all except specified)
       -timeout+          Timeout for requests (default 10 seconds)
       -Userdbs           Load only user databases, not the standard databases
                               all   Disable standard dbs and load only user dbs
                               tests Disable only db_tests and load udb_tests
       -useragent         Force User-Agent instead of pulling from database
       -url+              Target host/URL (alias of -host)
       -useproxy          Use the proxy defined in nikto.conf, or argument http://server:port
       -Version           Print plugin and database versions
       -vhost+            Virtual host (for Host header)
       -404code           Ignore these HTTP codes as negative responses (always). Format is "302,301".
       -404string         Ignore this string in response body content as negative response (always). Can be a regular expression.
            + requires a value
```

# Nikto DSL Matchers

Nikto's test database supports a mini-DSL for matching responses. The following matchers are supported:

- `BODY:` and `!BODY:` — Match or exclude content in the response body.
- `HEADER:` and `!HEADER:` — Match or exclude content in HTTP headers.
- `COOKIE:` and `!COOKIE:` — Match or exclude content in HTTP cookies. (NEW)
- `CODE:` and `!CODE:` — Match or exclude HTTP status codes.

You can combine multiple matchers with `&&` (AND). Example:

    BODY:login&&!BODY:logout&&HEADER:X-Powered-By&&COOKIE:sessionid

This will match if the response body contains "login", does not contain "logout", the headers include "X-Powered-By", and a cookie named "sessionid" is present.

License
=======
Copyright (C) 2001–2026 Chris Sullo. All rights reserved.

This license notice applies to: Nikto's code only

See [COPYING.LibWhisker](COPYING.LibWhisker) for LibWhisker licensing information.

Database files are NOT licensed under the GPL and may only be distributed as part of the official Nikto package or installer, for use exclusively with Nikto.

For full licensing terms and commercial use policies, visit:
https://cirt.net/Nikto-Licensing

This program is free software: you can redistribute it and/or modify  it under the terms of the GNU General Public License version 3,  as published by the Free Software Foundation.

This program is distributed in the hope that it will be useful,  but WITHOUT ANY WARRANTY; without even the implied warranty of  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the  GNU General Public License for more details.

The full license text is available at: https://www.gnu.org/licenses/gpl-3.0.txt

See [COPYING](COPYING) for the complete license notice.
