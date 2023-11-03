import argparse
import json

from requests import Session, Response
from typing import List, Optional


def main(
        domain: str,
        client_id: str,
        client_secret: str,
        query_filter: str,
        proxies: Optional[dict] = None,
        get_vulns: bool = False,
):
    session = Session()

    headers: dict = {
        'Accept': 'application/json',
        'Content-Type': 'application/json',
    }
    aid: Optional[str] = None
    device: Optional[dict] = None

    # authenticate
    try:
        body_params = {
            'client_id': client_id,
            'client_secret': client_secret,
        }
        resp_auth: Response = session.post(
            url=f'https://{domain}/oauth2/token',
            data=body_params,
            proxies=proxies,
        )
        resp_auth.raise_for_status()
        data_auth: dict = resp_auth.json()
        token = data_auth.get('access_token')
        headers['Authorization'] = f'Bearer {token}'
    except Exception as exc_auth:
        print(f'{exc_auth}')

    # query for agent ID
    try:
        resp_query: Response = session.get(
            url=f'https://{domain}/devices/queries/devices/v1',
            params={'filter': query_filter},
            headers=headers,
            proxies=proxies,
        )
        resp_query.raise_for_status()
        data_query: dict = resp_query.json()
        resources: list = data_query.get('resources')
        for resource in resources:
            aid = resource
        print(f'id: {aid}')
    except Exception as exc_query:
        print(f'{exc_query}')

    # query for device data
    try:
        resp_entity: Response = session.get(
            url=f'https://{domain}/devices/entities/devices/v1',
            params={'ids': aid},
            headers=headers,
            proxies=proxies,
        )
        resp_entity.raise_for_status()
        data_entity: dict = resp_entity.json()
        resources: list = data_entity.get('resources')
        for resource in resources:
            device = resource
        print(f'device: {device}')
    except Exception as exc_entity:
        print(f'{exc_entity}')

    # query for vulns data
    if get_vulns:
        vulnerabilities: list = []
        try:
            query_filters: List[str] = [f'aid:\'{aid}\'']
            url_params: dict = {
                'filter': '+'.join(query_filters),
                # 'limit': 1,
                # 'facet': ['cve', 'remediation'],
            }
            resp_vuln: Response = session.get(
                url=f'https://{domain}/spotlight/combined/vulnerabilities/v1',
                params=url_params,
                headers=headers,
                proxies=proxies,
            )
            resp_vuln.raise_for_status()
            data_vuln: dict = resp_vuln.json()
            resources: list = data_vuln.get('resources')
            for resource in resources:
                vulnerabilities.append(resource)
            print(f'device: {device}')
            device['vulnerabilities'] = vulnerabilities
        except Exception as exc_entity:
            print(f'{exc_entity}')
    return device


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '--client_id',
        type=str,
        help='The client_id of the API key',
        required=True,
        default=None
    )
    parser.add_argument(
        '--client_secret',
        type=str,
        help='The API key',
        required=True,
        default=None
    )
    parser.add_argument(
        '--hostname',
        type=str,
        help='The hostname to query for',
        required=False,
        default=None
    )
    parser.add_argument(
        '--filter',
        type=str,
        help='The query filter to use to filter the agent ID query results',
        required=False,
        default=None
    )
    parser.add_argument(
        '--domain',
        type=str,
        help="The FQDN for your Crowdstrike account's API",
        required=False,
        default='api.crowdstrike.com'
    )
    parser.add_argument(
        '--proxies',
        type=str,
        help="JSON structure specifying 'http' and 'https' proxy URLs",
        required=False,
    )
    parser.add_argument(
        '--vulns',
        type=bool,
        help="Get vulnerabilities for the specified host",
        default=False,
        required=False,
    )
    args = parser.parse_args()

    query_filter: str = ''
    if args.hostname and not args.filter:
        query_filter = f"hostname:'{args.hostname}'"
    elif args.filter:
        query_filter = args.filter

    proxies: Optional[dict] = None
    if proxies:
        try:
            proxies: dict = json.loads(args.proxies)
        except Exception as exc_json:
            print(f'WARNING: failure parsing proxies: {exc_json}: proxies provided: {proxies}')

    device = main(
        domain=args.domain,
        client_id=args.client_id,
        client_secret=args.client_secret,
        query_filter=query_filter,
        proxies=proxies,
        get_vulns=args.vulns,
    )

    if device:
        vulnerabilities: list = device.get('vulnerabilities')
        if vulnerabilities and isinstance(vulnerabilities, list):
            print(f'vulns count: {len(vulnerabilities)}')
        print(f'device info: {device or ""}')
    else:
        print('No devices found')
