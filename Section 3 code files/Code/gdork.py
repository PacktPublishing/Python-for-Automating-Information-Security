import argparse
import json
import requests
from typing import Dict

baseurl = 'https://www.googleapis.com/customsearch/v1'
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


def do_search(key: str, engine_id: str, dorks_file: str) -> Dict:
    """
    Perform Google dork searches specified in given dorks file against custom search API.
    :param key: custom search API key
    :param engine_id: custom search engine ID
    :param dorks_file: JSON file containing dorks to try
    :return: dictionary containing results
    """
    global baseurl
    params = {'key': key, 'cx': engine_id}
    with open(dorks_file, 'r') as f:
        dorks = json.load(f)
    links = {}
    for k, v in dorks.items():
        print_message('##### Trying dorks from category "{}". #####'.format(k))
        links[k] = []
        for d in v:
            description = d['description']
            dork = d['dork']
            print_message('### Trying dork for "{}". ###'.format(description))
            start_index = 1
            params['q'] = dork
            results = []
            while True:
                params['start'] = start_index
                response = requests.get(baseurl, params=params).json()
                if 'items' not in response:
                    break
                results.extend([link['link'] for link in response['items']])
                if 'nextPage' not in response['queries']:
                    break
                start_index = response['queries']['nextPage'][0]['startIndex']
            links[k].extend(results)
    return links


def main():
    global quiet

    parser = argparse.ArgumentParser(description='A tool to automate common Google dork searches for OSINT.',
                                     epilog='Before using this tool, create a new project using the "Get a Key" button at "https://developers.google.com/custom-search/v1/overview" and obtain the API key. Then, create a custom search engine at "https://cse.google.com/cse/create/new" and specify *.<domain> as the site to search, then obtain the engine ID. Provide the API key and engine ID as input arguments here.')
    parser.add_argument('-k', '--api-key', required=True, help='API key')
    parser.add_argument('-e', '--engine-id', required=True, help='Google custom search engine ID')
    parser.add_argument('dorks_file', help='JSON file containing Google dorks to test')
    parser.add_argument('-o', '--output', help='Output file to write to')
    parser.add_argument('-f', '--format', help='Output format (default is json)', default='json',
                        choices=['json', 'plain'])
    parser.add_argument('-q', '--quiet', help='Do not print informative messages', action='store_true')
    args = parser.parse_args()

    output = args.output
    output_format = args.format
    quiet = args.quiet
    api_key = args.api_key
    engine_id = args.engine_id
    dorks_file = args.dorks_file

    print_message('Starting search.')
    links = do_search(api_key, engine_id, dorks_file)

    # print results
    if output:
        print_message('Writing output to {}.'.format(output))
        with open(output, 'w') as of:
            if output_format == 'json':
                json.dump(links, of, indent=2)
            else:
                for k, v in links.items():
                    of.write('{} : {}\n'.format(k, v))
    else:
        print_message('Writing output to STDOUT.')
        if output_format == 'json':
            print(json.dumps(links, indent=2))
        else:
            for k, v in links.items():
                print('{} : {}'.format(k, v))


if __name__ == '__main__':
    main()
