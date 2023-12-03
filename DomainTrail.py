import argparse
import json
import os
import re
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

import dns.exception
import dns.query
import dns.resolver
import dns.zone
import requests
from bs4 import BeautifulSoup
from colorama import Fore, Style, init
from tqdm import tqdm

print_lock = threading.Lock()

def banner():
    banner = '''
    ┳┓       •  ┏┳┓    •┓
    ┃┃┏┓┏┳┓┏┓┓┏┓ ┃ ┏┓┏┓┓┃
    ┻┛┗┛┛┗┗┗┻┗┛┗ ┻ ┛ ┗┻┗┗ v1.1.0
    '''
    print(banner)

def main():
    banner()
    init(autoreset=True)
    parser = argparse.ArgumentParser(description="Subdomain enumeration script.")
    parser.add_argument("-d", "--domain", help="Specify the domain to enumerate subdomains.")
    parser.add_argument("-l", "--list", help="Specify a file with a list of domains to enumerate subdomains.", type=str)
    parser.add_argument("-p", "--passive", action="store_true", help="Use only passive enumeration methods.")
    parser.add_argument("-o", "--output", help="Output file to save the found subdomains.", type=str)
    parser.add_argument("-w", "--wordlist", help="Specify a wordlist for subdomain brute-forcing.", required=False)
    parser.add_argument("-t", "--threads", help="Number of threads for brute-forcing subdomains (defaults to 200)", type=int, default=200)
    args = parser.parse_args()

    if args.domain is None and args.list is None:
        print(Fore.RED + "Error: Either a domain (-d) or a list of domains (-l) must be specified.")
    
    if args.domain and args.list:
        print(Fore.RED + "Error: Please specify either a single domain (-d) or a list of domains (-l), but not both.")
        sys.exit(1)

    domains = [args.domain] if args.domain else []

    if args.list:
        try:
            with open(args.list, 'r') as file:
                domains.extend(file.read().splitlines())
        except FileNotFoundError:
            print(Fore.RED + f"Error: Domain list file not found: {args.list}")
            sys.exit(1)

    for domain in domains:
        if not validate_domain(domain):
            print(Fore.RED + f"Invalid domain format: {domain}. Please use domain.tld format.")
            continue

        found_subdomains = enumerate_subdomains(domain, args.passive, args.wordlist, args.threads)
        valid_subdomains = {subdomain for subdomain in set(found_subdomains) if validate_subdomain(subdomain, domain)}

        if args.output:
            with open(args.output, "a") as file:
                file.write(f"\n➜ Subdomains for {domain}\n\n")
                for subdomain in sorted(valid_subdomains):
                    file.write(subdomain + "\n")
        else:
            print(Fore.GREEN + f"\n✔ Found {len(valid_subdomains)} unique valid subdomains for {domain}.\n")
            for subdomain in sorted(valid_subdomains):   
                print(Fore.CYAN + f"{subdomain}")

def load_domains_from_file(filename):
    try:
        with open(filename, "r") as file:
            return [line.strip() for line in file if line.strip()]
    except FileNotFoundError:
        print(Fore.RED + f"✖ File not found: {filename}")
        sys.exit(1)

def validate_domain(domain):
    pattern = r"^(?!\-)([A-Za-z0-9\-]{1,63}(?<!\-)\.?)+[A-Za-z]{2,6}$"
    return re.match(pattern, domain)

def validate_subdomain(subdomain, domain):
    if subdomain.startswith('@') or subdomain.startswith('*'):
        return False    
    return subdomain.endswith(domain)

def enumerate_subdomains(domain, use_passive, wordlist=None, num_threads=200):
    print(Fore.BLUE + f"\nℹ Enumerating subdomains for {domain} using {'passive' if use_passive else 'active and passive'} methods\n")

    tasks = [t_crt, t_rapiddns, t_dnsdumpster, t_waybackmachine, t_anubis, t_subdomaincenter, t_otx, t_urlscan]
    found_subdomains = set()
    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = {executor.submit(task, domain) for task in tasks}
        for future in as_completed(futures):
            found_subdomains.update(subdomain.lower() for subdomain in future.result())

    new_subdomains = t_yahoo(domain, found_subdomains)
    found_subdomains.update(new_subdomains)

    if not use_passive:
        new_subdomains = t_zonetransfer(domain)
        found_subdomains.update(new_subdomains)
        brute_forced_subdomains = enumerate_from_wordlist(domain, wordlist, num_threads)
        found_subdomains.update(brute_forced_subdomains)

    return list(found_subdomains)

def t_zonetransfer(domain):
    found_subdomains = []
    zone_transfer_successful = False
    print(Fore.MAGENTA + f"\n➜ Attempting zone transfer for {domain}\n")

    try:
        ns_answer = dns.resolver.resolve(domain, 'NS')
        for server in ns_answer:
            try:
                ip_answer = dns.resolver.resolve(server.target, 'A')
                for ip in ip_answer:
                    try:
                        zone = dns.zone.from_xfr(dns.query.xfr(str(ip), domain))
                        zone_transfer_successful = True
                        for name, node in zone.nodes.items():
                            rdatasets = node.rdatasets
                            for rdataset in rdatasets:
                                for rdata in rdataset:
                                    if rdata.rdtype == dns.rdatatype.A:
                                        found_subdomains.append(str(name) + '.' + domain)
                    except dns.exception.FormError:
                        print(Fore.RED + f"✖ NS {server} refused zone transfer!")
                    except dns.xfr.TransferError:
                        print(Fore.YELLOW + f"⚠ Transfer refused for NS {server.target}.")
                        continue
            except dns.resolver.NoAnswer:
                print(Fore.YELLOW + f"➜ No A record for NS {server.target}")
                continue
    except dns.resolver.NoNameservers:
        print(Fore.RED + f"✖ No NS records found for domain {domain}")
    except dns.xfr.TransferError:
        print(Fore.YELLOW + f"⚠ Zone transfer request refused for domain {domain}")

    if zone_transfer_successful:
        print(Fore.GREEN + f"✔ Zone transfer was successful.")

    return list(set(found_subdomains))

def t_crt(domain):
    found_subdomains = []
    url = f"https://crt.sh/?q=%25.{domain}"
    user_agent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:59.0) Gecko/20100101 Firefox/59.0"
    headers = {"User-Agent": user_agent, "Referer": "https://crt.sh"}
    with print_lock:
        print(Fore.MAGENTA + f"➜ Attempting to find domains in Certificate Search for {domain}")

    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            soup = BeautifulSoup(response.content, 'html.parser')
            for row in soup.find_all('tr'):
                cells = row.find_all('td')
                if len(cells) > 4:
                    subdomain = cells[4].get_text().strip()
                    if subdomain.endswith(domain):
                        found_subdomains.append(subdomain)
        else:
            with print_lock:
                print(Fore.RED + f"✖ Request to Certificate Search failed with status code: {response.status_code}")
    except Exception as e:
        with print_lock:
            print(Fore.RED + f"✖ Could not enumerate using Certificate Search due to an error")

    return list(set(found_subdomains))

def t_rapiddns(domain):
    found_subdomains = []
    url = f"https://rapiddns.io/subdomain/{domain}?full=1#result"
    user_agent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:59.0) Gecko/20100101 Firefox/59.0"
    headers = {"User-Agent": user_agent, "Referer": "https://rapiddns.io"}
    with print_lock:
        print(Fore.MAGENTA + f"➜ Attempting to find domains in RapidDNS for {domain}")

    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            soup = BeautifulSoup(response.content, 'html.parser')
            for row in soup.find("table").find("tbody").find_all("tr"):
                cells = row.find_all('td')
                if len(cells) > 0:
                    subdomain = cells[0].get_text().strip()
                    if subdomain.endswith(domain):
                        found_subdomains.append(subdomain)
        else:
            with print_lock:
                print(Fore.RED + f"✖ Request to RapidDNS failed with status code: {response.status_code}")
    except Exception as e:
        with print_lock:
            print(Fore.RED + f"✖ Could not enumerate using RapidDNS due to an error")

    return list(set(found_subdomains))

def t_dnsdumpster(domain):
    found_subdomains = []
    url = "https://dnsdumpster.com"
    user_agent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:59.0) Gecko/20100101 Firefox/59.0"
    headers = {"User-Agent": user_agent, "Referer": "https://dnsdumpster.com"}
    with print_lock:
        print(Fore.MAGENTA + f"➜ Attempting to find domains in DNSdumpster for {domain}")

    try:
        session = requests.Session()
        session.headers.update(headers)
        resp = session.get(url)

        if resp.status_code == 200:
            csrf_token = re.compile('<input type="hidden" name="csrfmiddlewaretoken" value="(.*?)">', re.S).findall(resp.text)[0].strip()
            data = {
                "csrfmiddlewaretoken": csrf_token,
                "targetip": domain,
                "user": "free",
            }
            cookies = {"csrftoken": csrf_token}
            resp = session.post(url, data=data, cookies=cookies, headers=headers)

            if resp.status_code == 200:
                soup = BeautifulSoup(resp.content, 'html.parser')
                table_rows = soup.find_all('td', class_='col-md-4')
                for row in table_rows:
                    subdomain = row.get_text().split('<')[0].strip()
                    if subdomain.endswith(domain):
                        found_subdomains.append(subdomain)
            else:
                with print_lock:
                    print(Fore.RED + f"✖ Request to DNSdumpster failed with status code: {resp.status_code}")
        else:
            with print_lock:
                print(Fore.RED + f"✖ Failed to get csrf token from DNSdumpster with status code: {resp.status_code}")

    except Exception as e:
        with print_lock:
            print(Fore.RED + f"✖ Could not enumerate using DNSdumpster due to an error")

    return list(set(found_subdomains))

def t_waybackmachine(domain):
    found_subdomains = []
    url = f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=txt&fl=original&collapse=urlkey"
    user_agent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:59.0) Gecko/20100101 Firefox/59.0"
    headers = {"User-Agent": user_agent, "Referer": "https://web.archive.org"}
    with print_lock:
        print(Fore.MAGENTA + f"➜ Attempting to find domains in WaybackMachine for {domain}")

    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            urls = response.text.splitlines()
            for url in urls:
                parsed_url = urlparse(url)
                subdomain = parsed_url.netloc
                subdomain = re.sub(r":\d+", "", subdomain)
                if subdomain.endswith(domain):
                    found_subdomains.append(subdomain)
        else:
            with print_lock:
                print(Fore.RED + f"✖ Request to Wayback Machine failed with status code: {response.status_code}")
    except Exception as e:
        with print_lock:
            print(Fore.RED + f"✖ Could not enumerate using Wayback Machine due to an error")

    return list(set(found_subdomains))

def t_anubis(domain):
    found_subdomains = []
    url = f"https://jonlu.ca/anubis/subdomains/{domain}"
    user_agent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:59.0) Gecko/20100101 Firefox/59.0"
    headers = {"User-Agent": user_agent, "Referer": "https://jonlu.ca"}
    with print_lock:
        print(Fore.MAGENTA + f"➜ Attempting to find domains in Anubis for {domain}")

    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            subdomains = json.loads(response.text)
            for subdomain in subdomains:
                found_subdomains.append(subdomain)
        else:
            with print_lock:
                print(Fore.RED + f"✖ Request to Anubis failed with status code: {response.status_code}")
    except Exception as e:
        with print_lock:
            print(Fore.RED + f"✖ Could not enumerate using Anubis due to an error")

    return list(set(found_subdomains))

def t_subdomaincenter(domain):
    found_subdomains = []
    url = f"http://api.subdomain.center/?domain={domain}"
    user_agent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:59.0) Gecko/20100101 Firefox/59.0"
    headers = {"User-Agent": user_agent, "Referer": "https://api.subdomain.center"}
    with print_lock:
        print(Fore.MAGENTA + f"➜ Attempting to find domains in Subdomaincenter for {domain}")

    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            subdomains = json.loads(response.text)
            for subdomain in subdomains:
                found_subdomains.append(subdomain)
        else:
            with print_lock:
                print(Fore.RED + f"✖ Request to Subdomain Center failed with status code: {response.status_code}")
    except Exception as e:
        with print_lock:
            print(Fore.RED + f"✖ Could not enumerate using Subdomain Center due to an error")

    return list(set(found_subdomains))

def t_otx(domain):
    found_subdomains = []
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
    user_agent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:59.0) Gecko/20100101 Firefox/59.0"
    headers = {"User-Agent": user_agent, "Referer": "https://otx.alienvault.com"}
    with print_lock:
        print(Fore.MAGENTA + f"➜ Attempting to find domains in OTX for {domain}")

    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = json.loads(response.text)
            passive_dns = data.get("passive_dns", [])
            for record in passive_dns:
                hostname = record.get("hostname")
                if hostname:
                    found_subdomains.append(hostname)
                address = record.get("address")
                if address and not address.startswith(('http', 'https')):
                    found_subdomains.append(address)
        else:
            with print_lock:
                print(Fore.RED + f"✖ Request to OTX failed with status code: {response.status_code}")
    except Exception as e:
        with print_lock:
            print(Fore.RED + f"✖ Could not enumerate using OTX due to an error")

    return list(set(found_subdomains))

def t_urlscan(domain):
    found_subdomains = []
    url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}"
    user_agent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:59.0) Gecko/20100101 Firefox/59.0"
    headers = {"User-Agent": user_agent, "Referer": "https://urlscan.io"}
    with print_lock:
        print(Fore.MAGENTA + f"➜ Attempting to find domains in URLScan for {domain}")

    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            for result in data.get("results", []):
                page = result.get("page", {})
                subdomain = page.get("domain")
                if subdomain and subdomain.endswith(domain):
                    found_subdomains.append(subdomain.lower())
        else:
            with print_lock:
                print(Fore.RED + f"✖ Request to URLScan failed with status code: {response.status_code}")
    except Exception as e:
        with print_lock:
            print(Fore.RED + f"✖ Could not enumerate using URLScan due to an error")

    return list(set(found_subdomains))

def t_yahoo(domain, found_subdomains):
    yahoo_subdomains = set(found_subdomains)
    new_found = set()
    print(Fore.MAGENTA + f"➜ Attempting to find domains in Yahoo for {domain}")

    while True:
        query = ' -site:'.join([''] + [sub for sub in yahoo_subdomains if sub != domain] + list(new_found))
        url = f"https://search.yahoo.com/search?p={query}&vs={domain}"
        user_agent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:59.0) Gecko/20100101 Firefox/59.0"
        headers = {"User-Agent": user_agent, "Referer": "https://search.yahoo.com"}

        try:
            response = requests.get(url, headers=headers)
            if response.status_code != 200:
                print(Fore.RED + f"✖ Request to Yahoo failed with status code: {response.status_code}")
                break
            elif "We did not find results for" in response.text:
                break

            soup = BeautifulSoup(response.text, 'html.parser')
            links = soup.find_all('a', href=True)

            new_subdomains = set()
            for link in links:
                href = link['href']
                match = re.search(r'https?://([a-zA-Z0-9.-]+)\b', href)
                if match:
                    url = match.group(1)
                    if url.endswith(domain) and url not in yahoo_subdomains:
                        new_subdomains.add(url)

            if not new_subdomains:
                break

            new_found.update(new_subdomains)
            yahoo_subdomains.update(new_subdomains)

        except Exception as e:
            print(Fore.RED + f"✖ Error querying Yahoo")
            break

    return list(new_found)

def resolve(query):
    rdtypes = ["A", "AAAA", "CNAME"]
    answers = set()
    for rdtype in rdtypes:
        try:
            answers.update(str(answer) for answer in dns.resolver.resolve(query, rdtype=rdtype))
        except Exception:
            continue
    return answers

def enumerate_from_wordlist(domain, wordlist_path, num_threads):
    found_subdomains = set()

    script_dir = os.path.dirname(os.path.realpath(__file__))

    if not wordlist_path:
        wordlist_path = os.path.join(script_dir, "wordlists", "top13k-subdomains.txt")

    try:
        with open(wordlist_path, 'r') as file:
            lines = [line.strip() for line in file if line.strip()]
        total_lines = len(lines)
        print(Fore.MAGENTA + f"\n➜ Trying {total_lines} subdomains for {domain}\n")
    except FileNotFoundError:
        print(Fore.RED + f"\n✖ Wordlist file not found: {wordlist_path}\n")
        return found_subdomains

    def resolve_subdomain(subdomain):
        try:
            dns.resolver.resolve(subdomain, 'A')
            return subdomain
        except Exception:
            return None

    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        tasks = [executor.submit(resolve_subdomain, line + '.' + domain) for line in lines]

        for future in tqdm(as_completed(tasks), ncols=100, total=len(tasks), desc="Enumerating", unit="subdomain"):
            subdomain = future.result()
            if subdomain:
                found_subdomains.add(subdomain.lower())

    return found_subdomains

if __name__ == "__main__":
    main()