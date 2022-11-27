import dns.dnssec
import dns.flags
import dns.message
import dns.name
import dns.query

import constants
from dns_resolver import find_rr, custom_print, convert_to_dns_type, parse_args, create_list


def validate_key(ip, sub_domain, key):
    rrsig = None
    rrset = None
    request = dns.message.make_query(sub_domain, dns.rdatatype.DNSKEY, want_dnssec=True)
    response = dns.query.udp(request, ip, 2)
    if response.rcode() != dns.rcode.NOERROR or len(response.answer) < 2:
        raise Exception("DNS SEC not supported. Record not received.")
    for item in response.answer:
        if item.rdtype == dns.rdatatype.RRSIG:
            rrsig = item
        else:
            rrset = item
    if rrsig is None or rrset is None:
        raise Exception("DNS SEC not supported. Key not received.")
    if key is None:
        key = {sub_domain: rrset}
    try:
        dns.dnssec.validate(rrset, rrsig, key)
        return rrset
    except dns.dnssec.ValidationFailure as e:
        raise Exception(e)


def validate_zone_records(response, key):
    rrsets = []
    rrsig = None
    if len(response.answer) > 0:
        section = response.answer
        check_type = dns.rdatatype.A
    else:
        section = response.authority
        check_type = dns.rdatatype.DS
    for rrset in section:
        if rrset.rdtype == dns.rdatatype.RRSIG:
            rrsig = rrset
        elif rrset.rdtype == check_type:
            rrsets.append(rrset)
    for rrset in rrsets:
        try:
            dns.dnssec.validate(rrset, rrsig, key)
        except dns.dnssec.ValidationFailure as e:
            raise Exception(e)


def find_ds_record(response):
    ds_records = []
    for section in response.sections:
        for rrset in section:
            for item in rrset.items:
                if item.rdtype == dns.rdatatype.DS:
                    ds_records.append(item)
    return ds_records


def validate_ds_records(subdomain, key_set, ds_records):
    if len(ds_records) == 0:
        return True
    for ds in ds_records:
        for k in key_set:
            if ds.digest_type == 2:
                h = 'SHA256'
            else:
                h = 'SHA1'
            val_ds = dns.dnssec.make_ds(subdomain, k, h)
            if ds == val_ds:
                return True
    return False


def resolve_query(domain, dns_type, server_ip):
    domain = dns.name.from_text(domain)
    if not domain.is_absolute():
        domain = domain.concatenate(dns.name.troot)
    request = dns.message.make_query(domain, dns_type, want_dnssec=True)
    return dns.query.udp(request, server_ip)


def resolve_name(domain, dns_type, ip_list, ds_records, level):
    for ip in ip_list:
        url = domain.split('.')
        sub_domain = dns.name.from_text('.'.join(url[level - 1:]))
        try:
            # verify public ZSK of subdomain zone
            key_set = validate_key(ip, sub_domain, None)
        except Exception as e:
            if ip == ip_list[-1]:
                raise Exception(e)
            else:
                continue
        try:
            # validate KSK of subdomain using parent's DS record
            flag = validate_ds_records(sub_domain, key_set, ds_records)
            if not flag:
                raise Exception("Bad DNS Key. DNS Key KSK not Verified")
        except Exception as e:
            if ip == ip_list[-1]:
                raise Exception(e)
            else:
                continue
        key = {sub_domain: key_set}
        # fetch ds records and response by making the A type query with dnssec flag
        response = resolve_query(domain, dns_type, ip)
        ds_records = find_ds_record(response)
        try:
            # validate records for the zone using verified ZSK
            validate_zone_records(response, key)
        except Exception as e:
            if ip == ip_list[-1]:
                raise Exception(e)
            else:
                continue
        # resolve query at this level and fetch IPs to query for next level
        if len(response.answer) > 0:
            if dns_type == dns.rdatatype.A:
                response = find_rr(response.answer, dns.rdatatype.CNAME, dns_type, response)
            return response
        elif len(response.additional) > 0:
            ip_addresses = create_list(response.additional)
            return resolve_name(domain, dns_type, ip_addresses, ds_records, level - 1)
        elif len(response.authority) > 0:
            for rrset in response.authority:
                for item in rrset.items:
                    if item.rdtype == dns.rdatatype.NS:
                        response = find_ip(str(item.target), dns_type)
                        if len(response.answer) > 0:
                            ips = create_list(response.answer)
                            response = resolve_name(domain, dns_type, ips, ds_records, level - 1)
                            if len(response.answer) > 0:
                                return response
            return response
        else:
            return response


def find_ip(domain, dns_type):
    # validate root and start process for child NS
    if domain[-1] == '.':
        domain = domain[:-1]
    for ip in constants.ROOT_SERVER:
        # validate root ZSK
        root_set = validate_key(ip, '', {dns.name.root: constants.ROOT_KSK})
        key = {dns.name.root: root_set}
        root_query = resolve_query(domain, dns_type, ip)
        # validate root records
        validate_zone_records(root_query, key)
        # carry forward DS record to CHILD
        ds_records = find_ds_record(root_query)
        if len(root_query.additional) > 0:
            try:
                ip_list = create_list(root_query.additional)
                return resolve_name(domain, dns_type, ip_list, ds_records, len(domain.split('.')))
            except Exception as e:
                raise Exception(e)
    return None


def fetch_dnssec_record(d, d_type, output):
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
    output = open('dnssec_op.txt', 'w')
    if args.input_file is not None:
        with open(args.input_file) as file:
            for line in file:
                inp = line.split()
                temp = convert_to_dns_type(inp[1])
                output.write("======================================================\n")
                output.write("INPUT QUERY {} {} \n".format(inp[0], temp.name))
                output.write('\n')
                fetch_dnssec_record(inp[0], temp, output)
                output.write("======================================================\n \n")
    else:
        d = args.domain_name
        d_type = convert_to_dns_type(args.dns_type)
        output.write("======================================================\n")
        output.write("INPUT QUERY {} {} \n".format(d, d_type.name))
        output.write('\n')
        fetch_dnssec_record(d, d_type, output)
        output.write("======================================================\n \n")
    output.close()


if __name__ == '__main__':
    args = parse_args()
    main(args)
