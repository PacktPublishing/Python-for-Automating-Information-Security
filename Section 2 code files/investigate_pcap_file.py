import argparse
import json
from scapy.all import *
from typing import Dict

app_filters = {'ftp': 'tcp port 21', 'http': 'tcp port 80', 'telnet': 'tcp port 23'}


def handle_packets(packets, verbose=False):
    """
    Handle the gathered packets without regard to specific application.
    :param packets: an iterable object containing packets (could be a list or generator of some kind)
    :param verbose: boolean indicating whether to show just a summary (default) or the whole packet details (if true)
    :return: None
    """
    for pkt in packets:
        if verbose:
            print(pkt.show())
        else:
            print(pkt.summary())


def handle_ftp(packets) -> Dict:
    """
    Handle gathered FTP packets. We are looking for brute force/dictionary attacks against FTP.
    :param packets: an iterable object containing packets (could be a list or generator of some kind)
    :return: dictionary containing number of successful and failed login attempts per client IP
    """
    client_login_attempts = {}
    for pkt in packets:
        # make sure this is an FTP response from the server
        if Raw in pkt and pkt[TCP].sport == 21:
            load = pkt[Raw].load.decode()
            try:
                respond_code = int(load.split()[0])
            except:
                continue

            # failed or successful login
            if respond_code == 530 or respond_code == 230:
                client_ip = pkt[IP].dst
                if client_ip not in client_login_attempts:
                    client_login_attempts[client_ip] = {'failed': 0, 'successful': 0, 'attacker': False,
                                                        'message': None}
            # failed login
            if respond_code == 530:
                client_login_attempts[client_ip]['failed'] += 1
            # successful login
            elif respond_code == 230:
                client_login_attempts[client_ip]['successful'] += 1
    return client_login_attempts


def handle_http(packets):
    handle_packets(packets)


def handle_telnet(packets):
    handle_packets(packets, verbose=True)


def main():
    """
    Main logic.
    :return: None
    """
    global app_filters

    parser = argparse.ArgumentParser(
        description='A network packet sniffer looking for attacks against specific applications.')
    parser.add_argument('-a', '--application', help='Application to filter packets for', required=True,
                        choices=list(app_filters.keys()))
    parser.add_argument('-i', '--ip', help='IP address to filter packets for (source or destination)')
    parser.add_argument('-s', '--src-ip', help='Source IP address to filter packets for')
    parser.add_argument('-d', '--dst-ip', help='Destination IP address to filter packets for')
    parser.add_argument('-f', '--filter', help='Additional filter criteria for packets')
    parser.add_argument('-o', '--output', help='Output file to write to')
    parser.add_argument('pcap_file', help='PCAP file to read from')
    args = parser.parse_args()

    application = args.application.lower()
    packet_filter = app_filters[application]
    if args.ip:
        packet_filter = '{} and host {}'.format(packet_filter, args.ip)
    else:
        if args.src_ip:
            packet_filter = '{} and src host {}'.format(packet_filter, args.src_ip)
        elif args.dst_ip:
            packet_filter = '{} and dst host {}'.format(packet_filter, args.dst_ip)
    if args.filter:
        packet_filter = '{} and ({})'.format(packet_filter, args.filter)
    pcap_file = args.pcap_file
    output = args.output
    handle_function = globals()['handle_{}'.format(application)]

    # read and analyze packets
    print('Starting to read packets from file with filter "{}".'.format(packet_filter))
    with PcapReader(tcpdump(pcap_file, args=["-w", "-", packet_filter], getfd=True)) as pcap_reader:
        client_login_attempts = handle_function(pcap_reader)

    # check for attacks
    if client_login_attempts:
        print('Checking for brute force / dictionary attacks.')
        for k, v in client_login_attempts.items():
            failed = v['failed']
            if failed >= 5:
                v['attacker'] = True
                successful = v['successful']
                if successful == 0:
                    v['message'] = 'WARNING: Likely attacker but no successful logins detected.'
                else:
                    v['message'] = 'ALERT: Likely attacker with {} successful logins detected!'.format(successful)

        # print attack info to output
        if args.output:
            with open(output, 'w') as of:
                json.dump(client_login_attempts, of, indent=2)
        else:
            print(json.dumps(client_login_attempts, indent=2))


if __name__ == '__main__':
    main()
