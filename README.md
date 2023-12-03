![DomainTrail](https://github.com/gatete/DomainTrail/blob/main/img/domaintrail_logo.png)

## Description

DomainTrail is a fast subdomain enumeration tool designed to identify subdomains of a specific domain through various passive and active methods.

## Usage

DomainTrail can be used in two modes: Single domain enumeration or multiple domain enumeration from a list.

DomainTrail.py <-d DOMAIN | -l LIST> [OPTIONS]

```
-d --domain <domain>         Specify the target domain.
-l --list                    Specify a list of target domains.
-p --passive                 Use only passive enumeration methods.
-w --wordlist <wordlist>     Path to a custom wordlist for subdomain brute-forcing.
-t --threads <number>        Number of threads for DNS bruteforcing (defaults to 200).
-o --output <output>         Output file to save the found subdomains.
```

### Examples

- Enumerate subdomains for example.com using both passive and active techniques with the default wordlist and number of threads.
```
python3 DomainTrail.py -d example.com
```

- Enumerate subdomains for example.com using both passive and active techniques with a custom wordlist and number of threads.
```
python3 DomainTrail.py -d example.com -w wordlist.txt -t 300
```

- Enumerate subdomains for domains from a file using only passive techniques and write the output to a file.
```
python3 DomainTrail.py -l domains.txt -p -o example_subdomains.txt
```

## Setup

DomainTrail requires Python 3 and dnspython, request, beautifulsoup4, colorama and tqdm libraries.

```
git clone https://github.com/gatete/DomainTrail
cd DomainTrail
pip3 install -r requirements.txt
```

## License

This project is licensed under the Creative Commons Zero v1.0 Universal.
