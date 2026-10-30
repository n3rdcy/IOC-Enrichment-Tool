# IOC-Enrichment-Tool
PowerShell tool for automated IOC (Indicator of Compromise) enrichment using multiple threat intelligence sources.

<img width="370" height="333" alt="Captura de tela 2026-10-30 091051" src="https://github.com/user-attachments/assets/89dd10c7-447c-4a20-b119-6e8c8012914f" />

<img width="457" height="572" alt="image" src="https://github.com/user-attachments/assets/deb20eb0-8125-4de3-8807-e7d6edebedc1" />

<img width="580" height="485" alt="image" src="https://github.com/user-attachments/assets/696dd65c-b13f-4b39-ac20-62c68f247e12" />

# Features
IP reputation analysis
Domain reputation analysis
File hash reputation analysis
VirusTotal integration
AbuseIPDB integration
Cisco Talos integration
Quick access links for deeper investigation
Interactive console menu

# Supported Sources
IP Analysis:

VirusTotal
AbuseIPDB
Cisco Talos

Domain Analysis:

VirusTotal
Cisco Talos
MXToolbox

Hash Analysis:

VirusTotal
Cisco Talos

# Requirements
PowerShell 5.1+
VirusTotal API Key
AbuseIPDB API Key
Internet connectivity

# Configuration
Edit the following variables inside the script:

PowerShell
$VT_API = "YOUR_VIRUSTOTAL_API_KEY"
$ABUSE = "YOUR_ABUSEIPDB_API_KEY"

# Usage
Run the script:

PowerShell
.\IOC-Enrichment.ps1

Select the IOC type:

Plain Text
1 - IP
2 - Domain
3 - Hash
4 - Exit

# Sample Output

Plain Text
[+] VirusTotal

 
Malicious : 3
Suspicious: 1

 
[+] AbuseIPDB

 
Score : 83
Reports : 24
Country : US
ISP : Example ISP

 
[+] Cisco Talos

 
Threat Level : favorable
Reputation : 13
Hostname : example.domain
Organization : Example Org
Location : City, State, Country

# Author

Lucas Rezende
