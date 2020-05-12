import argparse
import json
import re
from typing import List

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


def get_matches(log_file: str, regex):
    """
    Generator object to generically parse a given log file using a compiled regex pattern.
    :param log_file: file to read logs from
    :param regex: compiled regex pattern
    :return: a generator, which when iterated returns tuples of captured groups
    """
    with open(log_file, 'r') as f:
        line = f.readline()
        while line:
            line = line.strip()
            matches = re.match(regex, line)
            if not matches:
                print_message('WARNING, unable to parse log message:   {}'.format(line))
                line = f.readline()
                continue
            groups = matches.groups()
            yield groups
            line = f.readline()


def parse_apache_error_logs(log_file: str) -> List:
    """
    Parse an apache error log file.
    :param log_file: log file to read from
    :return: list of dictionaries of fields parsed from logs
    """
    logs = []
    regex = re.compile(r'^\[(.+)\] \[(\w+)\] \[client (\d{1,3}(?:\.\d{1,3}){3})\] ([\w\s]+): (\S+)$', re.IGNORECASE)
    for groups in get_matches(log_file, regex):
        if groups[2] == '127.0.0.1':
            continue
        log_dict = {'datetime': groups[0], 'log_level': groups[1], 'client_ip': groups[2], 'message': groups[3],
                    'request_path': groups[4]}
        logs.append(log_dict)
    return logs


def parse_apache_logs(log_file: str) -> List:
    """
    Parse an apache access log file.
    :param log_file: log file to read from
    :return: list of dictionaries of fields parsed from logs
    """
    logs = []
    regex = re.compile(
        r'^(\d{1,3}(?:\.\d{1,3}){3}) \- \- \[(.+)\] "(\w+) (\S+) (\S+)" (\d+) ([\d\-]+) "(\S+)"(?: "(.+)")?$',
        re.IGNORECASE)
    for groups in get_matches(log_file, regex):
        if groups[0] == '127.0.0.1':
            continue
        log_dict = {'client_ip': groups[0], 'datetime': groups[1], 'request_method': groups[2],
                    'request_path': groups[3], 'protocol': groups[4], 'response_code': groups[5],
                    'response_size': groups[6], 'referer': groups[7], 'user_agent': groups[8]}
        logs.append(log_dict)
    return logs


def main():
    global quiet

    parser = argparse.ArgumentParser(description='Generic log file parser application.')
    parser.add_argument('-i', '--input', required=True, help='Log file to read from')
    parser.add_argument('-l', '--log-format', required=True, choices=['apache', 'apache_error'],
                        help='Type of log to parse')
    parser.add_argument('-o', '--output', help='Output file to write to')
    parser.add_argument('-q', '--quiet', help='Do not print informative messages', action='store_true')
    args = parser.parse_args()
    input_file = args.input
    log_format = args.log_format
    output = args.output
    quiet = args.quiet

    parse_function = globals()['parse_{}_logs'.format(log_format)]
    parsed_logs = parse_function(input_file)

    if output:
        with open(output, 'w') as of:
            json.dump(parsed_logs, of, indent=2)
    else:
        print(json.dumps(parsed_logs, indent=2))


if __name__ == '__main__':
    main()
