# Netenum

Netenum is a python script to automate the initial information gathering phase and service enumeration phase during an internal penetration test.

## Features
- Discover live hosts on the network using Nmap
- Perform thorough port scan on each host using Nmap
- Curl all the webpages hosted on the webserver to discover hidden webpages

## Installation
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Usage
```bash
sudo ./netenum.sh
```

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details
