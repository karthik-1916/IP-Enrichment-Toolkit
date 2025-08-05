# IP Enrichment Tool

This tool enriches IP addresses using multiple threat intelligence sources including VirusTotal, AbuseIPDB, GreyNoise, Shodan, IPInfo, and AlienVault OTX. Results are displayed in a formatted table using Rich.

## 📦 Installation

Clone the repository and install dependencies:
```
git clone https://github.com/karthik-1916/IP-Enrichment-Toolkit.git
cd IP-Enrichment-Toolkit
pip install -r requirements.txt
```

Copy the configuration template and add your API keys:
```
cp config_template.py config.py
# Edit config.py and add your API keys for each service
```

## 🛠️ Usage


Run the script with either a single IP or a file containing IPs:

### Enrich a single IP
```
python ip-enrichment.py -i <ip_address>
```

### Enrich IPs from a file
```
python ip-enrichment.py -f <filename>
```
Each line in the file should contain one IP address.

## ⚙️ Arguments

- `-i`, `--ip` : Enrich a single IP address.
- `-f`, `--file` : Enrich all IP addresses listed in a file.

## 📊 Output

For each IP, the tool displays:
- VirusTotal malicious score
- AbuseIPDB confidence score and usage type
- GreyNoise classification and tag
- ASN and geolocation (IPInfo)
- Open ports and detected services (Shodan)
- OTX pulse names and tags

## 📝 Notes

- API keys for all services must be set in `config.py`.
- Ensure you have network access to reach all APIs.
