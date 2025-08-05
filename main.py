import os
import requests
import threading
import multiprocessing
import shodan
from OTXv2 import OTXv2, IndicatorTypes
from rich.console import Console
from rich.table import Table
import argparse
import sys

console = Console(highlight=False, log_path=False, markup=True)

def print_banner():
    console.print("\n[bold magenta]" + "=" * 70 + "[/bold magenta]")
    console.print("[bold cyan]{:^70}[/bold cyan]".format("IP ENRICHMENT TOOLKIT"))
    console.print("[bold magenta]" + "=" * 70 + "[/bold magenta]")
    console.print("[bold white]{:<12}[/bold white][yellow]Karthik (DarkRavenOps)[/yellow]".format("Author:"))
    console.print("[bold white]{:<12}[/bold white][blue]https://github.com/karthik-1916/IP-Enrichment-Toolkit[/blue]".format("GitHub:"))
    console.print("[bold white]{:<12}[/bold white][green]https://darkravenops.in[/green]".format("Website:"))
    console.print("[bold magenta]" + "=" * 70 + "[/bold magenta]\n")






# Check for config.py existence
CONFIG_PATH = os.path.join(os.path.dirname(__file__), "config.py")
if not os.path.exists(CONFIG_PATH):
    print("[ERROR] config.py not found. Please create config.py with your API keys.")
    sys.exit(1)

from config import VT_API_KEY, ABUSE_API_KEY, GREYNOISE_API_KEY, SHODAN_API_KEY, OTX_API_KEY

console = Console(highlight=False, log_path=False, markup=True)

VT_HEADERS = {"x-apikey": VT_API_KEY}
ABUSE_HEADERS = {"Key": ABUSE_API_KEY, "Accept": "application/json"}
GREYNOISE_HEADERS = {"key": GREYNOISE_API_KEY, "Accept": "application/json"}

shodan_api = shodan.Shodan(SHODAN_API_KEY) if SHODAN_API_KEY else None
otx = OTXv2(OTX_API_KEY) if OTX_API_KEY else None



class IPEnricher:
    def __init__(self, ip):
        self.ip = ip
        self.result = {
            "ip": ip,
            "vt": "Pending",
            "abuse_score": "Pending",
            "usage": "Pending",
            "gn_class": "Pending",
            "gn_tag": "Pending",
            "asn": "Pending",
            "geo": "Pending",
            "ports": "Pending",
            "services": "Pending",
            "otx_pulse": "Pending",
            "otx_tags": "Pending"
        }

    def enrich(self):
        console.log(f"[bold green][INFO][/bold green] Starting enrichment for [cyan]{self.ip}[/cyan]")
        threads = []
        if VT_API_KEY:
            threads.append(threading.Thread(target=self.virustotal))
        else:
            self.result["vt"] = "Skipped (No API key)"
        if ABUSE_API_KEY:
            threads.append(threading.Thread(target=self.abuseipdb))
        else:
            self.result["abuse_score"] = "Skipped (No API key)"
            self.result["usage"] = "Skipped (No API key)"
        if GREYNOISE_API_KEY:
            threads.append(threading.Thread(target=self.greynoise))
        else:
            self.result["gn_class"] = "Skipped (No API key)"
            self.result["gn_tag"] = "Skipped (No API key)"
        # ipinfo does not require API key
        threads.append(threading.Thread(target=self.ipinfo))
        if SHODAN_API_KEY:
            threads.append(threading.Thread(target=self.shodan_lookup))
        else:
            self.result["ports"] = "Skipped (No API key)"
            self.result["services"] = "Skipped (No API key)"
        if OTX_API_KEY:
            threads.append(threading.Thread(target=self.otx_lookup))
        else:
            self.result["otx_pulse"] = "Skipped (No API key)"
            self.result["otx_tags"] = "Skipped (No API key)"
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.display_result()

    def virustotal(self):
        if not VT_API_KEY:
            self.result["vt"] = "Skipped (No API key)"
            return
        try:
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{self.ip}"
            response = requests.get(url, headers=VT_HEADERS)
            data = response.json()
            self.result["vt"] = data["data"]["attributes"]["last_analysis_stats"]["malicious"]
            console.log(f"[DEBUG] VT for {self.ip}: {self.result['vt']}")
        except Exception as e:
            self.result["vt"] = "Error"
            console.log(f"[red][ERROR][/red] VT error for {self.ip}: {e}")

    def abuseipdb(self):
        if not ABUSE_API_KEY:
            self.result["abuse_score"] = "Skipped (No API key)"
            self.result["usage"] = "Skipped (No API key)"
            return
        try:
            url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={self.ip}&maxAgeInDays=90"
            response = requests.get(url, headers=ABUSE_HEADERS)
            data = response.json()["data"]
            self.result["abuse_score"] = data["abuseConfidenceScore"]
            self.result["usage"] = data["usageType"]
            console.log(f"[DEBUG] AbuseIPDB for {self.ip}: {self.result['abuse_score']}")
        except Exception as e:
            self.result["abuse_score"] = "Error"
            self.result["usage"] = "Error"
            console.log(f"[red][ERROR][/red] AbuseIPDB error for {self.ip}: {e}")

    def greynoise(self):
        if not GREYNOISE_API_KEY:
            self.result["gn_class"] = "Skipped (No API key)"
            self.result["gn_tag"] = "Skipped (No API key)"
            return
        try:
            url = f"https://api.greynoise.io/v3/community/{self.ip}"
            response = requests.get(url, headers=GREYNOISE_HEADERS)
            data = response.json()
            self.result["gn_class"] = data.get("classification", "unknown")
            self.result["gn_tag"] = data.get("name", "N/A")
            console.log(f"[DEBUG] GreyNoise for {self.ip}: {self.result['gn_class']}")
        except Exception as e:
            self.result["gn_class"] = "Error"
            self.result["gn_tag"] = "Error"
            console.log(f"[red][ERROR][/red] GreyNoise error for {self.ip}: {e}")

    def ipinfo(self):
        # ipinfo does not require API key
        try:
            url = f"https://ipinfo.io/{self.ip}/json"
            response = requests.get(url)
            data = response.json()
            self.result["asn"] = data.get("org", "N/A")
            self.result["geo"] = f"{data.get('city', 'N/A')}, {data.get('region', 'N/A')}, {data.get('country', 'N/A')}"
            console.log(f"[DEBUG] IPInfo for {self.ip}: {self.result['asn']}")
        except Exception as e:
            self.result["asn"] = "Error"
            self.result["geo"] = "Error"
            console.log(f"[red][ERROR][/red] IPInfo error for {self.ip}: {e}")

    def shodan_lookup(self):
        if not SHODAN_API_KEY or not shodan_api:
            self.result["ports"] = "Skipped (No API key)"
            self.result["services"] = "Skipped (No API key)"
            return
        try:
            result = shodan_api.host(self.ip)
            ports = result.get("ports", [])
            services = []
            for item in result.get("data", []):
                product = item.get("product") or item.get("http", {}).get("server")
                if product:
                    services.append(str(product))
            self.result["ports"] = ", ".join(map(str, sorted(ports))) or "None"
            self.result["services"] = ", ".join(services) or "N/A"
            console.log(f"[DEBUG] Shodan for {self.ip}: Ports {ports}")
        except Exception as e:
            self.result["ports"] = "Error"
            self.result["services"] = "Error"
            console.log(f"[red][ERROR][/red] Shodan error for {self.ip}: {e}")

    def otx_lookup(self):
        if not OTX_API_KEY or not otx:
            self.result["otx_pulse"] = "Skipped (No API key)"
            self.result["otx_tags"] = "Skipped (No API key)"
            return
        try:
            details = otx.get_indicator_details_full(IndicatorTypes.IPv4, self.ip)
            pulses = details["general"]["pulse_info"]["pulses"]
            if pulses:
                pulse_names = [p["name"] for p in pulses[:2]]
                tags = pulses[0].get("tags", [])
                self.result["otx_pulse"] = ", ".join(pulse_names) or "None"
                self.result["otx_tags"] = ", ".join(tags) or "None"
            else:
                self.result["otx_pulse"] = "None"
                self.result["otx_tags"] = "None"
            console.log(f"[DEBUG] OTX for {self.ip}: {self.result['otx_pulse']}")
        except Exception as e:
            self.result["otx_pulse"] = "Error"
            self.result["otx_tags"] = "Error"
            console.log(f"[red][ERROR][/red] OTX error for {self.ip}: {e}")

    def display_result(self):
        table = Table(title=f"[bold blue]Enrichment Report for {self.ip}")
        table.add_column("Field", style="bold")
        table.add_column("Value", style="white")

        for key in [
            "vt", "abuse_score", "usage", "gn_class", "gn_tag", "asn",
            "geo", "ports", "services", "otx_pulse", "otx_tags"
        ]:
            table.add_row(key, str(self.result.get(key, "N/A")))
        console.print(table)
        console.rule("[bold grey]────────────────────────────────────")

def run_enricher(ip):
    enricher = IPEnricher(ip)
    enricher.enrich()

if __name__ == "__main__":
    # Show banner always
    print_banner()

    parser = argparse.ArgumentParser(
        description="IP Enrichment Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("-i", "--ip", help="Single IP address to enrich")
    parser.add_argument("-f", "--file", help="File containing list of IP addresses (one per line)")
    args = parser.parse_args()

    ip_list = []
    if args.ip:
        ip_list.append(args.ip)
    elif args.file:
        try:
            with open(args.file, "r") as f:
                ip_list = [line.strip() for line in f if line.strip()]
        except Exception as e:
            console.log(f"[red][ERROR][/red] Could not read file: {e}")
            sys.exit(1)
    else:
        console.log("[red][ERROR][/red] Please provide either -i <ip> or -f <file>")
        sys.exit(1)

    import time
    start_time = time.time()

    processes = []
    for ip in ip_list:
        p = multiprocessing.Process(target=run_enricher, args=(ip,))
        p.start()
        processes.append(p)
        
    for p in processes:
        p.join()

    end_time = time.time()
    elapsed = end_time - start_time
    console.print(f"\n[bold green]✔ Enrichment completed in {elapsed:.2f} seconds[/bold green]")
