# dns-resolver
Implemented the Dig Tool in a recursive manner for DNS as well as DNS SEC queries

## My Own DIG Tool 
In this repository I have implemented the DNS and DNSSEC resolver in an iterative manner.
I have also performed an experiment for analysing performance.

### Usage Instructions
NOTE: Creating an environment using conda/venv is recommended 
0. (if applicable) activate environment
1. cd into the root folder
2. pip install -r requirements.txt
3. Run below commands

#### DNS RESOLVER
* Command to run with args: python dns_resolver.py --domain-name "any-domain-name" --dns-type "supported type - A/NS/MX". If no dns-type given default is A.
* Command to run with input file: python dns_resolver.py --input-file "path to file"

#### DNSSEC RESOLVER
* Command to run with args: - python dnssec.py --domain-name "any-domain-name" --dns-type "A".
* Command to run with input file: - python dnssec.py --input-file "path to file"

### External Libraries Used
* dnspython
* matplotlib
* pandas
* datetime
* sys
* argparse
Footer
