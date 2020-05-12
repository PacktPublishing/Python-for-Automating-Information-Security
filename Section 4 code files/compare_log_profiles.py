import argparse
import json
from typing import List

"""
Potential additions:
    Check individual HTTP methods to determine typical ratios
    Check specific client profiles if given
    If DoS detected, detect specific offending client(s)
"""


def compare_apache_profiles(baseline_file, test_file, threshold=0.5) -> List:
    """
    Compare baseline Apache access log profile against test profile.
    :param baseline_file: file containing baseline profile
    :param test_file: file containing test profile
    :param threshold: percent (in decimal format) difference test profile must be from baseline to be considered malicious
    :return: list of results
    """
    results = []
    with open(baseline_file, 'r') as f:
        baseline_profile = json.load(f)
    with open(test_file, 'r') as f:
        test_profile = json.load(f)
    baseline_all_avg_per_min = baseline_profile['requests']['all']['avg_per_min']
    test_all_avg_per_min = test_profile['requests']['all']['avg_per_min']
    baseline_limit_avg_per_min = baseline_all_avg_per_min * (1 + threshold)
    if test_all_avg_per_min > baseline_limit_avg_per_min:
        result = {'category': 'Potential DoS Attack',
                  'details': {'baseline_profile_avg_per_min': baseline_all_avg_per_min,
                              'test_profile_avg_per_min': test_all_avg_per_min,
                              'baseline_profile_upper_limit': baseline_limit_avg_per_min,
                              'baseline_profile_threshold_percent': threshold * 100}}
        results.append(result)
    return results


def main():
    parser = argparse.ArgumentParser(
        description='This application compares a baseline log profile against another profile to look for malicious activity.')
    parser.add_argument('-b', '--baseline', required=True,
                        help='File containing baseline profile (JSON format) to read from')
    parser.add_argument('-t', '--test-file', required=True,
                        help='File containing test profile (JSON format) to read from')
    parser.add_argument('-p', '--percent-threshold', default=50,
                        help='Percent difference test profile must be from baseline profile to be considered malicious')
    parser.add_argument('-l', '--log-format', required=True, choices=['apache'], help='Type of log profile to parse')
    parser.add_argument('-o', '--output', help='Output file to write to')
    args = parser.parse_args()

    baseline_file = args.baseline
    test_file = args.test_file
    threshold = int(args.percent_threshold) / 100
    log_format = args.log_format
    output = args.output

    compare_profiles_function = globals()['compare_{}_profiles'.format(log_format)]
    profile = compare_profiles_function(baseline_file, test_file, threshold)

    if output:
        with open(output, 'w') as of:
            json.dump(profile, of, indent=2)
    else:
        print(json.dumps(profile, indent=2))


if __name__ == '__main__':
    main()
