import json
import logging
from nmap import PortScanner
from typing import Dict, Tuple


class Discovery:
    """
    Host discovery functions.
    """

    def __init__(self, logger=logging):
        """
        Initialize class.
        :param logger: application logger
        """
        self.logger = logger

    def get_ports(self, host: str, services_scan=True, ports='1-65535', opts='-Pn', speed=4):
        """
        Scan for open ports (and services if specified) on given host.
        :param host: host to scan
        :param services_scan: if True, scan for service details, otherwise scan for open ports only; default is True
        :param ports: ports to scan; default is 1-65535
        :param opts: NMAP flags
        :param speed: NMAP scan speed from 1-5; default is 4
        :param sudo: whether or not to scan using sudo; default is False
        :return:
        """
        nm = PortScanner()
        opts = '{} -T{}'.format(opts, speed)
        if services_scan:
            opts = '{} -sV'.format(opts)
        else:
            opts = '{} -sS'.format(opts)
        results = nm.scan(hosts=host, ports=ports, arguments=opts)
        ports_details = results['scan']
        self.logger.debug(json.dumps(ports_details, indent=2))
        return ports_details

    def get_os(self, host: str, opts='-Pn', speed=4, sudo=True) -> Dict:
        """
        Scan for OS details of provided hosts.
        :param host: host to scan
        :param opts: NMAP flags
        :param speed: NMAP scan speed from 1-5; default is 4
        :param sudo: whether or not to scan using sudo; default is True
        :return: dictionary of host details
        """
        nm = PortScanner()
        results = nm.scan(hosts=host, arguments='-O {} -T{}'.format(opts, speed), sudo=sudo)
        host_details = results['scan']
        self.logger.debug(json.dumps(host_details, indent=2))
        return host_details

    def do_discovery(self, host: str, ports='1-65535', opts='-Pn', sudo=False) -> Tuple:
        """
        Run discovery functions on the specified host.
        :param host: host to scan
        :param ports: ports to scan; default is 1-65535
        :param opts: NMAP flags
        :param sudo: whether or not to scan OS using sudo
        :return: tuple in format (ports details, OS details)
        """
        nm = PortScanner()
        self.logger.info('Checking to make sure host {} is reachable.'.format(host))
        results = nm.scan(hosts=host, arguments='-PE -n -sn')
        if len(list(results['scan'].keys())) < 1:
            self.logger.error('Error, I was unable to reach host {}.'.format(host))
            return None, None
        self.logger.info('Scanning ports {} on host {}.'.format(ports, host))
        ports_details = self.get_ports(host, ports=ports, opts=opts)
        self.logger.info('Determining OS of host {}.'.format(host))
        os_details = self.get_os(host, opts=opts, sudo=sudo)
        return ports_details, os_details
