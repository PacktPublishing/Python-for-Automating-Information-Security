import argparse
import json

"""
Potential additions:
    Check individual HTTP methods to determine typical ratios
    Check specific client profiles if given
    If DoS detected, detect specific offending client(s)
"""


def compare_profiles(baseline_file, test_file, threshold=0.5):
    results = []
    with open(baseline_file, 'r') as f:
        baseline_profile = json.load(f)
    with open(test_file, 'r') as f:
        test_profile = json.load(f)
    baseline_avg_pps = baseline_profile['avg_pps']
    baseline_packets_sessions_ratio = baseline_profile['packets_to_sessions_ratio']
    test_avg_pps = test_profile['avg_pps']
    test_packets_sessions_ratio = test_profile['packets_to_sessions_ratio']
    baseline_avg_pps_upper_limit = baseline_avg_pps * (1 + threshold)
    baseline_avg_pps_lower_limit = baseline_avg_pps * (1 - threshold)
    baseline_packets_sessions_upper_limit = baseline_packets_sessions_ratio * (1 + threshold)
    baseline_packets_sessions_lower_limit = baseline_packets_sessions_ratio * (1 - threshold)
    if test_avg_pps > baseline_avg_pps_upper_limit or test_avg_pps < baseline_avg_pps_lower_limit:
        result = {'category': 'Anomalous Packets per Second',
                  'details': {'baseline_profile_avg_pps': baseline_avg_pps, 'test_profile_avg_pps': test_avg_pps,
                              'baseline_profile_upper_limit': baseline_avg_pps_upper_limit,
                              'baseline_profile_lower_limit': baseline_avg_pps_lower_limit,
                              'baseline_profile_threshold_percent': threshold * 100}}
        results.append(result)
    if test_packets_sessions_ratio > baseline_packets_sessions_upper_limit or test_packets_sessions_ratio < baseline_packets_sessions_lower_limit:
        result = {'category': 'Anomalous Packets to Sessions Ratio',
                  'details': {'baseline_profile_packets_sessions_ratio': baseline_packets_sessions_ratio,
                              'test_profile_packets_sessions_ratio': test_packets_sessions_ratio,
                              'baseline_profile_upper_limit': baseline_packets_sessions_upper_limit,
                              'baseline_profile_lower_limit': baseline_packets_sessions_lower_limit,
                              'baseline_profile_threshold_percent': threshold * 100}}
        results.append(result)
    return results


def main():
    parser = argparse.ArgumentParser(
        description='This application compares a baseline network traffic profile against another profile to look for malicious/anomalous activity.')
    parser.add_argument('-b', '--baseline', required=True,
                        help='File containing baseline profile (JSON format) to read from')
    parser.add_argument('-t', '--test-file', required=True,
                        help='File containing test profile (JSON format) to read from')
    parser.add_argument('-p', '--percent-threshold', default=50,
                        help='Percent difference test profile must be from baseline profile to be considered malicious/anomalous')
    parser.add_argument('-o', '--output', help='Output file to write to')
    args = parser.parse_args()

    baseline_file = args.baseline
    test_file = args.test_file
    threshold = int(args.percent_threshold) / 100
    output = args.output

    analysis = compare_profiles(baseline_file, test_file, threshold)

    if output:
        with open(output, 'w') as of:
            json.dump(analysis, of, indent=2)
    else:
        print(json.dumps(analysis, indent=2))


if __name__ == '__main__':
    main()
