import sys
import argparse

import dns.flags
import dns.name
import dns.message
import dns.query
import constants
from datetime import datetime


# function to make the udp resolution calls using the dnspython library
def resolve_query(domain, dns_type, server_ip):
    domain = dns.name.from_text(domain)
    if not domain.is_absolute():
        domain = domain.concatenate(dns.name.root)
    request = dns.message.make_query(domain, dns_type)
    return dns.query.udp(request, server_ip)


# helper function that decides based on rdatatype if recurse for new domain or stop
def find_rr(section, check_type, dns_type, response):
    for rrset in section:
        for item in rrset.items:
            if item.rdtype == check_type:
                return find_ip(str(item.target), dns_type)
            else:
                return response


# helper function that scans through objects and returns the IPs
def create_list(section, check_type=dns.rdatatype.A):
    ip_addresses = []
    for rrset in section:
        for item in rrset.items:
            if item.rdtype == check_type:
                ip_addresses.append(item.address)
    return ip_addresses


# main logic on next steps to resolve a domain of given dns type
def resolve_name(domain, dns_type, ip_list):
    for ip in ip_list:
        response = resolve_query(domain, dns_type, ip)
        # first check if we have an answer
        if len(response.answer) > 0:
            # if A type check if CNAME response and further resolve else return
            if dns_type == dns.rdatatype.A:
                response = find_rr(response.answer, dns.rdatatype.CNAME, dns_type, response)
            return response
        # next check additional section for any further IPs to ask for resolving
        elif len(response.additional) > 0:
            ip_addresses = create_list(response.additional, dns.rdatatype.A)
            return resolve_name(domain, dns_type, ip_addresses)
        # lastly if new NS given check the authority section
        elif len(response.authority) > 0:
            # keep checking for IP till we get an answer to return
            for rrset in response.authority:
                for item in rrset.items:
                    if item.rdtype == dns.rdatatype.NS:
                        response = find_ip(str(item.target), dns_type)
                        if len(response.answer) > 0:
                            ips = create_list(response.answer, dns.rdatatype.A)
                            response = resolve_name(domain, dns_type, ips)
                            if len(response.answer) > 0:
                                return response
            return response
        else:
            return response


# main function that controls recursion call
def find_ip(domain, dns_type):
    return resolve_name(domain, dns_type, constants.ROOT_SERVER)


def custom_print(response, domain, dns_type, output):
    output.write('QUESTION SECTION: \n')
    output.write(str(domain) + "       IN      " + dns_type.name + '\n')
    output.write('\n')
    ips = []
    if len(response.answer) > 0:
        output.write('ANSWER SECTION: \n')
        name = response.answer[0].name
        domain = dns.name.from_text(domain)
        if not domain.is_absolute():
            domain = domain.concatenate(dns.name.root)
        if name != domain:
            output.write(str(domain) + "       IN      " + " CNAME " + str(name) + '\n')
        for rrset in response.answer:
            for item in rrset.items:
                if item.rdtype == dns.rdatatype.MX:
                    ips.append(str(item.exchange))
                elif item.rdtype == dns.rdatatype.NS:
                    ips.append(str(item.target))
                elif item.rdtype == dns.rdatatype.A:
                    ips.append(str(item.address))
                elif item.rdtype == dns.rdatatype.RRSIG:
                    ips.append(item)
                output.write(str(domain) + "      IN      " + item.rdtype.name + "   " + str(ips[-1]) + '\n')
        output.write('\n')

    if len(ips) == 0:
        output.write('AUTHORITY SECTION: \n')
        for rrset in response.authority:
            for item in rrset.items:
                if item.rdtype == dns.rdatatype.A:
                   ips.append(str(item.target))
                elif item.rdtype == dns.rdatatype.SOA:
                    ips.append(str(item.mname))
                output.write(str(domain) + "      IN      " + item.rdtype.name + "   " + str(ips[-1]) + '\n')
        output.write('\n')

    output.write("Query time: {:.2f} msec \n".format(response.time * 1000))
    curr_time = datetime.now()
    output.write("WHEN: " + curr_time.strftime("%a %b %-d %-H:%-M:%-S %Y") + '\n')
    output.write("MSG SIZE rcvd: " + str(sys.getsizeof(response)) + " bytes \n")
    output.write('\n')


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--domain-name', type=str, help='Domain Name to resolve the DNS')
    parser.add_argument('--dns-type', type=str, help='Type of DNS Query')
    parser.add_argument('--input-file', type=str, help='File with list of queries for resolution')
    args, _ = parser.parse_known_args()
    return args


def convert_to_dns_type(d_type):
    if d_type == 'A':
        return dns.rdatatype.A
    elif d_type == 'MX':
        return dns.rdatatype.MX
    elif d_type == 'NS':
        return dns.rdatatype.NS
    else:
        # find for A if input type is not supported
        return dns.rdatatype.A


def fetch_dns_record(d, d_type, output):
    try:
        result = find_ip(d, d_type)
        if result is None:
            raise Exception("No response received")
        if result.rcode() != dns.rcode.NOERROR:
            raise Exception("Did not resolve. Received Rcode {}".format(result.rcode()))
        custom_print(result, d, d_type, output)
    except Exception as e:
        output.write("Following exception occurred \n")
        output.write(str(e))
        output.write('\n')


def main(args):
    output = open('mydig_output.txt', 'w')
    if args.input_file is not None:
        with open(args.input_file) as file:
            for line in file:
                inp = line.split()
                temp = convert_to_dns_type(inp[1])
                output.write("======================================================\n")
                output.write("INPUT QUERY {} {} \n".format(inp[0], temp.name))
                output.write('\n')
                fetch_dns_record(inp[0], temp, output)
                output.write("======================================================\n \n")

    else:
        d = args.domain_name
        d_type = convert_to_dns_type(args.dns_type)
        output.write("======================================================\n")
        output.write("INPUT QUERY {} {} \n".format(d, d_type.name))
        output.write('\n')
        fetch_dns_record(d, d_type, output)
        output.write("======================================================\n \n")
    output.close()


if __name__ == '__main__':
    args = parse_args()
    main(args)
