import argparse
from scapy.all import *

quiet = False
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


def handle_tcp(packet):
    global interesting_tcp_ports

    app = None
    sport = packet[TCP].sport
    dport = packet[TCP].dport
    if sport in interesting_tcp_ports:
        app = interesting_tcp_ports[sport]
    elif dport in interesting_tcp_ports:
        app = interesting_tcp_ports[dport]
    print_message('Handling packet proto=TCP, sport={}, dport={}'.format(sport, dport))
    if not app:
        print('Handling TCP packet')
        print_message(packet.summary())
    else:
        handle_function = globals()['handle_{}'.format(app)]
        handle_function(packet)


def handle_udp(packet):
    global interesting_udp_ports

    app = None
    sport = packet[UDP].sport
    dport = packet[UDP].dport
    if sport in interesting_udp_ports:
        app = interesting_udp_ports[sport]
    elif dport in interesting_udp_ports:
        app = interesting_udp_ports[dport]
    print_message('Handling packet proto=UDP, sport={}, dport={}'.format(sport, dport))
    if not app:
        print('Handling UDP packet')
        print_message(packet.summary())
    else:
        handle_function = globals()['handle_{}'.format(app)]
        handle_function(packet)


def handle_icmp(packet):
    print('Handling ICMP packet')
    print_message(packet.summary())


def handle_ftp(packet):
    print('Handling FTP packet')
    print_message(packet.summary())


def handle_dns(packet):
    print('Handling DNS packet')
    print_message(packet.summary())


def handle_http(packet):
    print('Handling HTTP packet')
    print_message(packet.summary())


def handle_smtp(packet):
    print('Handling SMTP packet')
    print_message(packet.summary())


def handle_snmp(packet):
    print('Handling SNMP packet')
    print_message(packet.summary())


def handle_telnet(packet):
    print('Handling Telnet packet')
    print_message(packet.summary())


def handle_ldap(packet):
    print('Handling LDAP packet')
    print_message(packet.summary())


def handle_packet(packet):
    global proto_table

    if IP not in packet:
        return

    proto = proto_table[packet[IP].proto]
    handle_function = globals()['handle_{}'.format(proto)]
    print()
    handle_function(packet)


def main():
    global quiet

    parser = argparse.ArgumentParser(description='A general-purpose network packet sniffer.')
    parser.add_argument('-f', '--filter', help='Set a filter to capture specific packets')
    parser.add_argument('-i', '--iface', help='Listen on the specified interface')
    parser.add_argument('-o', '--output', help='Output file to write to')
    parser.add_argument('-q', '--quiet', help='Do not print informative messages', action='store_true')
    args = parser.parse_args()
    quiet = args.quiet
    kwargs = {'prn': handle_packet, 'store': False}
    if args.filter:
        kwargs['filter'] = args.filter
    if args.iface:
        kwargs['iface'] = args.iface
    sniff(**kwargs)


if __name__ == '__main__':
    main()
