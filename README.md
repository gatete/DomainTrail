# DomainTrail

## Description

DomainTrail is a subdomain enumeration tool designed to identify subdomains of a specific domain through various passive and active methods.

## Usage

DomainTrail.py -d DOMAIN [OPTIONS]

```
-d --domain:         Specify the target domain.
-p --passive:        Use only passive enumeration methods.
-w --wordlist:       Path to a custom wordlist for subdomain brute-forcing.
-t --threads:        Number of threads for brute-forcing.
-o --output:         Output file to save the found subdomains.
```

### Examples

- Enumerate subdomains for example.com using both passive and active techniques with the default wordlist and number of threads.
```
python3 DomainTrail.py -d example.com
```

- Enumerate subdomains for example.com using both passive and active techniques with a custom wordlist and number of threads.
```
python3 DomainTrail.py -d example.com -w wordlist.txt -t 10
```

- Enumerate subdomains for example.com using only passive techniques and write the output to a file.
```
python3 DomainTrail.py -d example.com -p -o example_subdomains.txt
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
