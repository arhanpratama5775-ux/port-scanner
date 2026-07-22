# Port Scanner

A simple TCP port scanner for checking which ports are open on a target machine. Useful for basic security auditing.

## What it does

Connects to each port on the target host and checks if it accepts connections. Uses multiple threads to scan quickly. Shows open ports with their associated service names.

## Requirements

Python 3.6+. No external packages needed.

## Usage

Scan common ports:
```
python scanner.py 192.168.1.1
```

Scan specific ports:
```
python scanner.py 192.168.1.1 -p 80,443,8080
```

Scan a range:
```
python scanner.py 192.168.1.1 -p 1-1000
```

Target by hostname:
```
python scanner.py example.com -p 22,80,443
```

Adjust timeout:
```
python scanner.py 192.168.1.1 -t 0.5
```

## Default ports scanned

21 (FTP), 22 (SSH), 23 (Telnet), 25 (SMTP), 53 (DNS), 80 (HTTP), 110 (POP3), 135, 139, 143 (IMAP), 443 (HTTPS), 445 (SMB), 993, 995, 1723, 3306 (MySQL), 3389 (RDP), 5432 (PostgreSQL), 5900 (VNC), 8080, 8443.

## License

MIT
