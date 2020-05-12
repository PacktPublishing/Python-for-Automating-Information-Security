import argparse
from base64 import b64decode
from scapy.all import *

quiet = False
output = None
interesting_tcp_ports = {21: 'ftp', 23: 'telnet', 25: 'smtp', 80: 'http'}
interesting_udp_ports = {53: 'dns', 161: 'snmp', 389: 'ldap'}
proto_table = {1: 'icmp', 6: 'tcp', 17: 'udp'}


def print_message(message: str):
    """
    Print message to STDOUT if the quiet option is set to False (this is the default).
    :param message: message to print
    :return: None
    """
    global quiet
    if not quiet:
        print(message)


def print_creds(message: str):
    """
    Print capture credentials to STDOUT and output file (if specified).
    :param message: message to print
    :return: None
    """
    global output
    print(message)
    if output:
        with open(output, 'a+') as of:
            of.write('{}\n'.format(message))


def handle_tcp(packet):
    """
    Handle a captured TCP packet.
    :param packet: captured packet
    :return: None
    """
    global interesting_tcp_ports

    app = None
    sport = packet[TCP].sport
    dport = packet[TCP].dport
    if sport in interesting_tcp_ports:
        app = interesting_tcp_ports[sport]
        server_addr = packet[IP].src
    elif dport in interesting_tcp_ports:
        app = interesting_tcp_ports[dport]
        server_addr = packet[IP].dst
    print_message('Handling packet proto=TCP, sport={}, dport={}'.format(sport, dport))
    if not app:
        print('Handling TCP packet')
        print_message(packet.summary())
    else:
        handle_function = globals()['handle_{}'.format(app)]
        handle_function(packet, server_addr)


def handle_udp(packet):
    """
    Handle a captured UDP packet.
    :param packet: captured packet
    :return: None
    """
    global interesting_udp_ports

    app = None
    sport = packet[UDP].sport
    dport = packet[UDP].dport
    if sport in interesting_udp_ports:
        app = interesting_udp_ports[sport]
        server_addr = packet[IP].src
    elif dport in interesting_udp_ports:
        app = interesting_udp_ports[dport]
        server_addr = packet[IP].dst
    print_message('Handling packet proto=UDP, sport={}, dport={}'.format(sport, dport))
    if not app:
        print('Handling UDP packet')
        print_message(packet.summary())
    else:
        handle_function = globals()['handle_{}'.format(app)]
        handle_function(packet, server_addr)


def handle_icmp(packet):
    """
    Handle a captured ICMP packet.
    :param packet: captured packet
    :return: None
    """
    print('Handling ICMP packet')
    print_message(packet.summary())


def handle_dns(packet, server_addr: str):
    """
    Handle a captured DNS packet.
    :param packet: captured packet
    :param server_addr: address of server the packet originated from or was destined for
    :return: None
    """
    print('Handling DNS packet')
    print_message(packet.summary())


def handle_ftp(packet, server_addr: str):
    """
    Handle a captured FTP packet.
    :param packet: captured packet
    :param server_addr: address of server the packet originated from or was destined for
    :return: None
    """
    print('Handling FTP packet')
    print_message(packet.summary())


def handle_http(packet, server_addr: str):
    """
    Handle a captured HTTP packet.
    :param packet: captured packet
    :param server_addr: address of server the packet originated from or was destined for
    :return: None
    """
    print('Handling HTTP packet')
    http_host = None
    basic_auth = None
    other_auth = None
    if Raw in packet:
        http_content = packet[Raw].load.decode().splitlines()
        for line in http_content:
            if re.search(r'^Host:', line):
                http_host = line.split()[-1]
            elif re.search(r'^Authorization:', line):
                if re.search(r'^Authorization: Basic', line):
                    basic_auth = line.split()[-1]
                else:
                    other_auth = line
            if http_host and (basic_auth or other_auth):
                break
    if basic_auth:
        tmp = b64decode(basic_auth).decode().split(':')
        username = tmp[0]
        password = tmp[1]
        print_creds(
            'Captured HTTP basic auth credentials! server={}, hostname={}, username={}, password={}'.format(server_addr,
                                                                                                            http_host,
                                                                                                            username,
                                                                                                            password))
    if other_auth:
        print_creds(
            'Captured HTTP auth credentials! server={}, hostname={}, creds_string="{}"'.format(server_addr, http_host,
                                                                                               other_auth))


def handle_ldap(packet, server_addr: str):
    """
    Handle a captured LDAP packet.
    :param packet: captured packet
    :param server_addr: address of server the packet originated from or was destined for
    :return: None
    """
    print('Handling LDAP packet')
    print_message(packet.summary())


def handle_smtp(packet, server_addr: str):
    """
    Handle a captured SMTP packet.
    :param packet: captured packet
    :param server_addr: address of server the packet originated from or was destined for
    :return: None
    """
    print('Handling SMTP packet')
    print_message(packet.summary())


def handle_snmp(packet, server_addr: str):
    """
    Handle a captured SNMP packet.
    :param packet: captured packet
    :param server_addr: address of server the packet originated from or was destined for
    :return: None
    """
    snmp_versions = {0: '1', 1: '2c'}
    print('Handling SNMP packet')
    if SNMP not in packet:
        print('Cannot read SNMP data, likely is SNMPv3.')
        return
    version = snmp_versions[packet[SNMP].version.val]
    community = packet[SNMP].community.val.decode()
    print_creds('Captured SNMPv{} credentials! server={}, community={}'.format(version, server_addr, community))


def handle_telnet(packet, server_addr: str):
    """
    Handle a captured Telnet packet.
    :param packet: captured packet
    :param server_addr: address of server the packet originated from or was destined for
    :return: None
    """
    print('Handling Telnet packet')
    print_message(packet.summary())


def handle_packet(packet):
    """
    Generic method to handle a captured packet.
    :param packet: captured packet
    :return: None
    """
    global proto_table

    if IP not in packet:
        return

    proto = proto_table[packet[IP].proto]
    handle_function = globals()['handle_{}'.format(proto)]
    print()
    handle_function(packet)


def main():
    """
    Main logic.
    :return: None
    """
    global quiet
    global output

    parser = argparse.ArgumentParser(description='A general-purpose network packet sniffer.')
    parser.add_argument('-f', '--filter', help='Set a filter to capture specific packets')
    parser.add_argument('-i', '--iface', help='Listen on the specified interface')
    parser.add_argument('-o', '--output', help='Output file to write to')
    parser.add_argument('-q', '--quiet', help='Do not print informative messages', action='store_true')
    args = parser.parse_args()
    quiet = args.quiet
    output = args.output

    kwargs = {'prn': handle_packet, 'store': False}
    if args.filter:
        kwargs['filter'] = args.filter
    if args.iface:
        kwargs['iface'] = args.iface

    sniff(**kwargs)


if __name__ == '__main__':
    main()
