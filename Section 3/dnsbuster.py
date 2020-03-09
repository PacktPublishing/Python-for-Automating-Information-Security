import argparse
import dns.query
import dns.resolver
import dns.zone
import json
from typing import Dict, List

quiet = False


def print_message(message: str):
    """
    Print message to STDOUT if the quiet option is set to False (this is the default).
    :param message: message to print
    :return: None
    """
    global quiet
    if not quiet:
        print(message)


def get_ns(tlz: str, soa=False) -> List:
    """
    Get a list of nameservers for the specified top-level zone.
    :param tlz: top-level zone to search
    :param soa: if True, gather SOA records instead of NS (default is NS)
    :return: list of name servers
    """
    servers = []
    if not soa:
        ns = dns.resolver.query(tlz, 'NS')
        sn = [x.to_text() for x in ns]
    else:
        ns = dns.resolver.query(tlz, 'SOA')
        sn = [x.mname.to_text() for x in ns]
    for name in sn:
        ips = dns.resolver.query(name, 'A')
        for rdata in ips:
            servers.append(rdata.address)
    return servers


def do_xfr(tlz: str, server: str):
    """
    Attempt to perform a zone transfer for the specified top-level zone.
    :param tlz: top-level zone for transfer attempt
    :param server: target nameserver
    :return: zone transfer results if successful, None otherwise
    """
    # TODO: finish handling errors and successes
    try:
        z = dns.zone.from_xfr(dns.query.xfr(server, tlz, timeout=3.0))
        return z
    except:
        return None


def do_enum(tlz: str, subdomains_file: str, resolver=dns.resolver) -> Dict:
    """
    Enumerate subdomains for the specified top-level zone.
    :param tlz: top-level zone to enumerate
    :param subdomains_file: file with a list of common subdomains to query
    :param resolver: resolver object (default is system resolver)
    :return: dictionary of domain names and their rdata
    """
    domains = {}
    with open(subdomains_file, 'r') as f:
        for sub in f:
            sub = sub.strip()
            qname = '{}.{}'.format(sub, tlz)
            try:
                q = resolver.query(qname)
                a = [a.address for a in q]
                domains[qname] = a
            except Exception as e:
                print_message(e)
                continue
    return domains


def main():
    """
    Main logic.
    :return: None
    """
    global quiet

    parser = argparse.ArgumentParser(description='A smart-ish DNS enumeration tool.')
    parser.add_argument('-x', '--skip-xfr',
                        help='Skip zone transfer attempt (default is to attempt before enumerating)',
                        action='store_true')
    parser.add_argument('-s', '--server', help='Specify DNS server to query (default is to use system resolver)')
    parser.add_argument('-o', '--output', help='Output file to write to')
    parser.add_argument('-f', '--format', help='Output format (default is json)', default='json',
                        choices=['json', 'plain'])
    parser.add_argument('-q', '--quiet', help='Do not print informative messages', action='store_true')
    parser.add_argument('-n', '--no-address', help='Print only the valid subdomains (do not print the rdata)',
                        action='store_true')
    parser.add_argument('tlz', help='Top-level zone to enumerate (i.e. google.com)')
    parser.add_argument('subdomains_file', help='File containing a list of subdomains to enumerate')
    args = parser.parse_args()

    server = args.server
    skip_xfr = args.skip_xfr
    output = args.output
    output_format = args.format
    quiet = args.quiet
    no_address = args.no_address
    tlz = args.tlz
    subdomains_file = args.subdomains_file

    soa_server = get_ns(tlz, soa=True)[0]
    resolver = dns.resolver
    if server:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [server]

    if not skip_xfr:
        print_message('Trying zone transfer.')
        results = do_xfr(tlz, soa_server)
        # TODO: if xfr succeeds, try xfr for all gathered subdomains
    # if xfr does not succeed or we chose to skip it, enumerate
    print_message('Enumerating subdomains.')
    domains = do_enum(tlz, subdomains_file, resolver)
    # print results
    if output:
        print_message('Writing output to {}.'.format(output))
        with open(output, 'w') as of:
            if output_format == 'json':
                if no_address:
                    json.dump(list(domains.keys()), of, indent=2)
                else:
                    json.dump(domains, of, indent=2)
            else:
                for k, v in domains.items():
                    if no_address:
                        of.write('{}\n'.format(k))
                    else:
                        of.write('{} : {}\n'.format(k, v))
    else:
        print_message('Writing output to STDOUT.')
        if output_format == 'json':
            if no_address:
                print(json.dumps(list(domains.keys()), indent=2))
            else:
                print(json.dumps(domains, indent=2))
        else:
            for k, v in domains.items():
                if no_address:
                    print(k)
                else:
                    print('{} : {}'.format(k, v))


if __name__ == '__main__':
    main()
