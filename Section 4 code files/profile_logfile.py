import argparse
from datetime import datetime as dt
import json
from typing import Dict

"""
Potential additions:
    Profile specific clients
    Check for burst traffic (time-series analysis)
    Check for number of different paths requested (may be able to detect scanning activity)
"""


def parse_timestamp(ts_string: str, ts_format: str):
    """
    Parse a given string with the given datetime format and return the corresponding Unix epoch timestamp.
    :param ts_string: string containing a datetime object of some kind
    :param ts_format: format string presumably matching the format of ts_string
    :return: number of seconds since epoch
    """
    return dt.strptime(ts_string, ts_format).timestamp()


def profile_apache_logs(input_file: str) -> Dict:
    """
    Create a log profile from a parsed Apache access log file.
    :param input_file: Apache access log file (JSON format)
    :return: dictionary with profiled statistics
    """
    apache_ts_format = '%d/%b/%Y:%H:%M:%S %z'
    with open(input_file, 'r') as f:
        logs = json.load(f)
    baseline = {'requests': {'all': {'total': 0}}, 'methods_breakdown': {}}
    first_datetime = None
    last_datetime = None
    for log in logs:
        if not first_datetime:
            first_datetime = log['datetime']
        baseline['requests']['all']['total'] += 1
        method = log['request_method'].lower()
        if method not in baseline['methods_breakdown']:
            baseline['methods_breakdown'][method] = 0
        baseline['methods_breakdown'][method] += 1
        last_datetime = log['datetime']

    earliest_timestamp = parse_timestamp(first_datetime, apache_ts_format)
    latest_timestamp = parse_timestamp(last_datetime, apache_ts_format)
    baseline['first_timestamp'] = earliest_timestamp
    baseline['last_timestamp'] = latest_timestamp
    baseline['seconds_elapsed'] = latest_timestamp - earliest_timestamp
    baseline['minutes_elapsed'] = baseline['seconds_elapsed'] / 60
    baseline['requests']['all']['avg_per_sec'] = baseline['requests']['all']['total'] / baseline['seconds_elapsed']
    baseline['requests']['all']['avg_per_min'] = baseline['requests']['all']['total'] / baseline['minutes_elapsed']

    for k, v in baseline['methods_breakdown'].items():
        baseline['requests'][k] = {'total': v}
        baseline['requests'][k]['avg_per_sec'] = v / baseline['seconds_elapsed']
        baseline['requests'][k]['avg_per_min'] = v / baseline['minutes_elapsed']

    del baseline['methods_breakdown']
    return baseline


def main():
    parser = argparse.ArgumentParser(
        description='This application calculates a log profile from a provided parsed log file.')
    parser.add_argument('-i', '--input', required=True, help='Parsed log file (JSON format) to read from')
    parser.add_argument('-l', '--log-format', required=True, choices=['apache'], help='Type of log to parse')
    parser.add_argument('-o', '--output', help='Output file to write to')
    args = parser.parse_args()

    input_file = args.input
    log_format = args.log_format
    output = args.output

    profile_function = globals()['profile_{}_logs'.format(log_format)]
    profile = profile_function(input_file)

    if output:
        with open(output, 'w') as of:
            json.dump(profile, of, indent=2)
    else:
        print(json.dumps(profile, indent=2))


if __name__ == '__main__':
    main()
