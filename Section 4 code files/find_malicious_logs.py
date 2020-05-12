import argparse
import json
from typing import List

"""
Potential additions:
    Check for blank referer value (a large number of these may indicate scanning)
"""

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


def analyze_apache_error_logs(input_file: str) -> List:
    """
    Placeholder for analyzing parsed Apache error log file.
    :param input_file: Apache error log file (JSON format)
    :return: list of malicious logs
    """
    pass


def analyze_apache_logs(input_file: str, http_response_code_threshold=0.5) -> List:
    """
    Analyze parsed Apache access log file to find malicious activity.
    :param input_file: Apache access log file (JSON format)
    :param http_response_code_threshold: HTTP response code ratio under which to flag as malicious
    :return: list of malicious logs
    """
    malicious_logs = []
    http_response_ratios = {}
    with open(input_file, 'r') as f:
        logs = json.load(f)
    # look for specific message types and count number of HTTP 200 response codes versus error codes
    for log in logs:
        if 'Nmap Scripting Engine' in log['user_agent']:
            mal_data = {'category': 'NMAP Scanning', 'client_ip': log['client_ip'], 'datetime': log['datetime']}
            malicious_logs.append(mal_data)
        if log['client_ip'] not in http_response_ratios:
            http_response_ratios[log['client_ip']] = {'200': 0, 'error': 0}
        if log['response_code'] != '200':
            http_response_ratios[log['client_ip']]['error'] += 1
        else:
            http_response_ratios[log['client_ip']]['200'] += 1
        http_response_ratios[log['client_ip']]['datetime'] = log['datetime']
    # process HTTP response code ratios and append to malicious logs if ratio is under given threshold
    for k, v in http_response_ratios.items():
        http_200 = v['200']
        http_error = v['error']
        total = http_200 + http_error
        ratio = http_200 / total
        if ratio < http_response_code_threshold:
            v['ratio'] = ratio
            v['category'] = 'Web Directory Enumeration'
            tmp_dict = {'category': 'Web Directory Enumeration', 'client_ip': k, 'datetime': v['datetime']}
            malicious_logs.append(tmp_dict)
    return malicious_logs


def main():
    global quiet

    parser = argparse.ArgumentParser(
        description='This application analyzes parsed log files to find malicious activity.')
    parser.add_argument('-i', '--input', required=True, help='Parsed log file (JSON format) to read from')
    parser.add_argument('-l', '--log-format', required=True, choices=['apache'], help='Type of log to parse')
    parser.add_argument('-o', '--output', help='Output file to write to')
    parser.add_argument('-q', '--quiet', help='Do not print informative messages', action='store_true')
    args = parser.parse_args()

    input_file = args.input
    log_format = args.log_format
    output = args.output
    quiet = args.quiet

    analyze_function = globals()['analyze_{}_logs'.format(log_format)]
    malicious_logs = analyze_function(input_file)

    if output:
        with open(output, 'w') as of:
            json.dump(malicious_logs, of, indent=2)
    else:
        print(json.dumps(malicious_logs, indent=2))


if __name__ == '__main__':
    main()
