import argparse
import json

from requests import Session, Response
from typing import List, Optional, Union


def main(
        domain: str,
        client_id: str,
        client_secret: str,
        query_filter: str,
        proxies: Optional[dict] = None,
        list_vulns: bool = False,
        list_scripts: bool = False,
        use_discover: bool = False,
) -> Union[None, str, list, dict]:
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

    if query_filter:
        # query for agent ID
        try:
            query_url: str = f'https://{domain}/devices/queries/devices/v1'
            if use_discover:
                query_url = f'https://{domain}/discover/queries/hosts/v1'
            resp_query: Response = session.get(
                url=query_url,
                params={'filter': query_filter},
                headers=headers,
                proxies=proxies,
            )
            resp_query.raise_for_status()
            data_query: dict = resp_query.json()
            resources: list = data_query.get('resources')
            for resource in resources:
                aid = resource
            # print(f'id: {aid}')
        except Exception as exc_query:
            print(f'{exc_query}')

        # query for device data
        try:
            entities_url: str = f'https://{domain}/devices/entities/devices/v1'
            if use_discover:
                entities_url = f'https://{domain}/discover/entities/hosts/v1'
            resp_entity: Response = session.get(
                url=entities_url,
                params={'ids': aid},
                headers=headers,
                proxies=proxies,
            )
            resp_entity.raise_for_status()
            data_entity: dict = resp_entity.json()
            resources: list = data_entity.get('resources')
            for resource in resources:
                device = resource
            # print(f'device: {device}')
        except Exception as exc_entity:
            print(f'{exc_entity}')

        # query for vulns data
        if list_vulns:
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
                device['vulnerabilities'] = vulnerabilities
            except Exception as exc_entity:
                print(f'{exc_entity}')
        return device

    elif list_scripts:
        # query for script IDs
        script_ids: list = []
        try:
            resp_query: Response = session.get(
                url=f'https://{domain}/real-time-response/queries/scripts/v1',
                params={'filter': query_filter},
                headers=headers,
                proxies=proxies,
            )
            resp_query.raise_for_status()
            data_query: dict = resp_query.json()
            script_ids = data_query.get('resources') or []
        except Exception as exc_query:
            print(f'{exc_query}')

        # query for scripts details
        resources: Optional[list] = None
        try:
            resp_entity: Response = session.get(
                url=f'https://{domain}/real-time-response/entities/scripts/v2',
                params={'ids': script_ids},
                headers=headers,
                proxies=proxies,
            )
            resp_entity.raise_for_status()
            data_entity: dict = resp_entity.json()
            resources: list = data_entity.get('resources')
        except Exception as exc_entity:
            print(f'{exc_entity}')
        return resources


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '--client-id',
        default=None,
        type=str,
        required=True,
        help='The client_id of the API key',
        dest='client_id',
    )
    parser.add_argument(
        '--client-secret',
        default=None,
        type=str,
        required=True,
        help='The API key',
        dest='client_secret',
    )
    parser.add_argument(
        '--discover',
        default=None,
        type=bool,
        required=False,
        help='use Discover endpoints',
    )
    parser.add_argument(
        '--hostname',
        default=None,
        type=str,
        required=False,
        help='The hostname to query for',
    )
    parser.add_argument(
        '--filter',
        default=None,
        type=str,
        required=False,
        help='The query filter to use to filter the agent ID query results',
    )
    parser.add_argument(
        '--domain',
        default='api.crowdstrike.com',
        type=str,
        required=False,
        help="The FQDN for your Crowdstrike account's API (not full URL)",
    )
    parser.add_argument(
        '--proxies',
        type=str,
        required=False,
        help="JSON structure specifying 'http' and 'https' proxy URLs",
    )
    parser.add_argument(
        '--list-vulns',
        action='store_true',
        default=False,
        required=False,
        help="Get vulnerabilities for the specified host",
        dest='list_vulns',
    )
    parser.add_argument(
        '--list-scripts',
        action='store_true',
        default=False,
        required=False,
        help="List RTR custom scripts details",
        dest='list_scripts',
    )

    args = parser.parse_args()

    query_filter: Optional[str] = None
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

    result = main(
        domain=args.domain,
        client_id=args.client_id,
        client_secret=args.client_secret,
        query_filter=query_filter,
        proxies=proxies,
        list_vulns=args.list_vulns,
        list_scripts=args.list_scripts,
        use_discover=args.discover or False,
    )

    if result:
        if args.list_vulns:
            vulnerabilities: list = result.get('vulnerabilities')
            if vulnerabilities and isinstance(vulnerabilities, list):
                print(f'vulns count: {len(vulnerabilities)}')
        print(json.dumps(result, indent=4))
    else:
        print('No results found')
