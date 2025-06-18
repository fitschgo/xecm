__author__ = "Philipp Egger"
__copyright__ = "Copyright (C) 2025, Philipp Egger"
__credits__ = ["Philipp Egger"]
__maintainer__ = "Philipp Egger"
__email__ = "philipp.egger@handel-it.com"

import logging
import requests
import enum
import urllib.parse
import json

class LoginType(enum.Enum):
    OTCS_TICKET = enum.auto()
    OTDS_TICKET = enum.auto()
    OTDS_BEARER = enum.auto()

class CSRestAPI:
    """ Do Login and get OTCSTicket, OTDSTicket or Bearer Token """
    __logger: logging.Logger
    __useragent = 'Chrome XECM'
    __base_url = ''
    __ticket = ''
    __usr = ''
    __pwd = ''
    __login_type: LoginType
    __volumes_hash = {}

    def __init__(
        self,
        login_type: LoginType,
        login_url: str,
        user_or_client_id: str,
        pw_or_client_secret: str,
        logger: logging.Logger
    ) -> None:
        """Initialize the XECMLogin class.

        Args:
            login_type (LoginType):
                The type of login OTCSTicket, OTDSTicket or OTDSBearerToken
            login_url (str):
                The base URL of the OTCS or OTDS Server.
            user_or_client_id (str):
                The username of the user or client ID of the oAuth2 client (depending on the login_type).
            pw_or_client_secret (str):
                The password of the user or client secret of the oAuth2 client (depending on the login_type).
            logger (logging.Logger, optional - set to None if not needed):
                The logging object to use for all log messages.

        """
        try:
            # check logger
            if logger:
                self.__logger = logger
            else:
                self.__logger = None

            self.__login_type = login_type

            # url check if last char is / and add it if missing
            self.__base_url = self.__check_url(login_url)
            self.__usr = user_or_client_id
            self.__pwd = pw_or_client_secret

            # check login_type OTCS_TICKET or OTDS_TICKET or OTDS_BEARER (default)
            if self.__login_type == LoginType.OTCS_TICKET:
                if self.__logger:
                    self.__logger.info(f'Create OTCSTicket with username and password.')
                self.__ticket = self.__otcs_login(self.__usr, self.__pwd)
                if self.__logger:
                    self.__logger.info(f'OTCSTicket created.')
            elif self.__login_type == LoginType.OTDS_TICKET:
                if self.__logger:
                    self.__logger.info(f'Create OTDSTicket with username and password.')
                self.__ticket = self.__otds_login(self.__usr, self.__pwd)
                if self.__logger:
                    self.__logger.info(f'OTDSTicket created.')
            else:
                if self.__logger:
                    self.__logger.info(f'Create Bearer Token in OTDS with client_id and client_secret.')
                self.__ticket = self.__otds_token(self.__usr, self.__pwd)
                if self.__logger:
                    self.__logger.info(f'Bearer Token created.')

        except Exception as innerErr:
            error_message = f'XECMLogin Error during init: {innerErr}.'
            if self.__logger:
                self.__logger.info(error_message)
            raise Exception(error_message)

        if self.__logger:
            self.__logger.info(f'XECMLogin successful: {self.__ticket}')

    def __otcs_login(self, username: str, password: str) -> str:
        """Do login at Content Server and return the OTCSTicket.

        Args:
            username (str):
                The username of the ContentServer user.
            password (str):
                The password of the ContentServer user.

        Returns:
            str: OTCSTicket

        """

        error_message = ''
        otcsticket = ''
        apiendpoint = 'api/v1/auth'
        url = urllib.parse.urljoin(self.__base_url, apiendpoint)

        params = { 'username': username, 'password': password }

        # do REST API call to CS
        r = requests.post(url=url, data=params,
                          headers={'User-Agent': self.__useragent,
                                   'Content-Type': 'application/x-www-form-urlencoded'})

        if self.__logger:
            self.__pretty_print_POST(r.request)

        if r.ok:
            # get OTCSTicket from response
            r_text = r.text

            if self.__logger:
                self.__logger.debug(f'-----------RESPONSE-----------\r\n{r_text}')

            try:
                resObj = json.loads(r_text)
                otcsticket = resObj.get('ticket', '')
            except Exception as innerErr:
                error_message = f'Login Error OTCSTicket on {url} on Result Parse: {innerErr}. Response was {r_text}'
                if self.__logger:
                    self.__logger.error(error_message)
                raise Exception(error_message)

            if otcsticket == '':
                error_message = f'Login Error on {url}: no OTCS ticket created. Response was {r_text}'
                if self.__logger:
                    self.__logger.error(error_message)
                raise Exception(error_message)

        else:
            error_message = f'Login Error on {url}: {r.status_code} {r.text}'
            if self.__logger:
                self.__logger.error(error_message)
            raise Exception(error_message)

        return otcsticket

    def __otds_login(self, username: str, password: str) -> str:
        """Do login at OTDS and return the OTDSTicket.

        Args:
            username (str):
                The username of the OTDS user.
            password (str):
                The password of the OTDS user.

        Returns:
            str: OTDSTicket

        """

        error_message = ''
        otdsticket = ''
        apiendpoint = 'otdsws/v1/authentication/credentials'
        url = urllib.parse.urljoin(self.__base_url, apiendpoint)

        params = { 'user_name': username, 'password': password }

        # do REST API call to CS
        r = requests.post(url=url, data=json.dumps(params),
                          headers={'User-Agent': self.__useragent,
                                   'Content-Type': 'application/json;charset=utf-8'})

        if self.__logger:
            self.__pretty_print_POST(r.request)

        if r.ok:
            # get OTDSTicket from response
            r_text = r.text

            if self.__logger:
                self.__logger.debug(f'-----------RESPONSE-----------\r\n{r_text}')

            try:
                resObj = json.loads(r_text)
                otdsticket = resObj.get('ticket', '')
            except Exception as innerErr:
                error_message = f'Login Error OTDSTicket on {url} on Result Parse: {innerErr}. Response was {r_text}'
                if self.__logger:
                    self.__logger.error(error_message)
                raise Exception(error_message)

            if otdsticket == '':
                error_message = f'Login Error on {url}: no OTDS ticket created. Response was {r_text}'
                if self.__logger:
                    self.__logger.error(error_message)
                raise Exception(error_message)

        else:
            error_message = f'Login Error on {url}: {r.status_code} {r.text}'
            if self.__logger:
                self.__logger.error(error_message)
            raise Exception(error_message)

        return otdsticket

    def __otds_token(self, client_id: str, client_secret: str) -> str:
        """Do login at OTDS and return the Bearer Token.

        Args:
            client_id (str):
                The client id of the OTDS oAuth2 client.
            client_secret (str):
                The client secret of the OTDS oAuth2 client.

        Returns:
            str: Bearer Token

        """

        error_message = ''
        bearer_token = ''
        apiendpoint = 'otdsws/oauth2/token'
        url = urllib.parse.urljoin(self.__base_url, apiendpoint)

        params = { 'grant_type': 'client_credentials', 'requested_token_type': 'urn:ietf:params:oauth:token-type:access_token' }

        # do REST API call to CS
        r = requests.post(url=url, data=params,
                          headers={'User-Agent': self.__useragent,
                                   'Content-Type': 'application/x-www-form-urlencoded'}, auth=(client_id, client_secret))

        if self.__logger:
            self.__pretty_print_POST(r.request)

        if r.ok:
            # get OTDSTicket from response
            r_text = r.text

            if self.__logger:
                self.__logger.debug(f'-----------RESPONSE-----------\r\n{r_text}')

            try:
                resObj = json.loads(r_text)
                bearer_token = resObj.get('access_token', '')
            except Exception as innerErr:
                error_message = f'Login Error Bearer Token on {url} on Result Parse: {innerErr}. Response was {r_text}'
                if self.__logger:
                    self.__logger.error(error_message)
                raise Exception(error_message)

            if bearer_token == '':
                error_message = f'Login Error on {url}: no OTDS Bearer Token created. Response was {r_text}'
                if self.__logger:
                    self.__logger.error(error_message)
                raise Exception(error_message)

        else:
            error_message = f'Login Error on {url}: {r.status_code} {r.text}'
            if self.__logger:
                self.__logger.error(error_message)
            raise Exception(error_message)

        return bearer_token

    def __pretty_print_POST(self, req: requests.PreparedRequest) -> None:
        """Pretty Print request to log

        Args:
            req (PreparedRequest):
                The request instance.

        Returns:
            None

        """
        if self.__logger:
            self.__logger.debug('{}\n{}\r\n{}\r\n\r\n{}'.format(
                '-----------REQUEST-----------',
                req.method + ' ' + req.url,
                '\r\n'.join('{}: {}'.format(k, v) for k, v in req.headers.items()),
                req.body,
            ))

    def __pretty_print_GET(self, req: requests.PreparedRequest) -> None:
        """Pretty Print request to log

        Args:
            req (PreparedRequest):
                The request instance.

        Returns:
            None

        """
        if self.__logger:
            self.__logger.debug('{}\n{}\r\n{}\r\n'.format(
                '-----------REQUEST-----------',
                req.method + ' ' + req.url,
                '\r\n'.join('{}: {}'.format(k, v) for k, v in req.headers.items())
            ))

    def __check_url(self, url: str) -> str:
        """Check URL for trailing / and add it if needed.

        Args:
            url (str):
                The URL to be checked.

        Returns:
            str: URL with trailing /

        """
        retval = url
        if retval and retval != '' and len(retval) > 1:
            if retval[-1] != '/':
                retval += '/'
        return retval

    def call_get(self, api_url: str, params: dict) -> str:
        """Generic Call Content Server API with GET method.

        Args:
            api_url (str):
                The URL to be called. I.e. http://content-server/otcs/cs.exe

            params (dict):
                URL parameters as dictionary. I.e. { 'id': node_id } -> ?id=<node_id>

        Returns:
            str: JSON result of API call

        """
        error_message = ''
        retval = ''

        # do REST API call to CS
        auth_header = ''
        auth_ticket = ''
        if self.__login_type == LoginType.OTCS_TICKET:
            auth_header = 'OTCSTicket'
            auth_ticket = self.__ticket
        elif self.__login_type == LoginType.OTDS_TICKET:
            auth_header = 'OTDSTicket'
            auth_ticket = self.__ticket
        else:
            auth_header = 'Authorization'
            auth_ticket = f'Bearer {self.__ticket}'

        r = requests.get(url=api_url,
                         headers={'Content-Type': 'application/json', auth_header: auth_ticket,
                                  'User-Agent': self.__useragent}, params=params)

        if self.__logger:
            self.__pretty_print_GET(r.request)

        if r.ok:
            try:
                retval = r.text

                if self.__logger:
                    self.__logger.debug(f'-----------RESPONSE-----------\r\n{r.text}')

            except Exception as innerErr:
                error_message = f'Error in call_get() -> {api_url}: {innerErr}\n{r.text}'
                if self.__logger:
                    self.__logger.error(error_message)
                raise Exception(error_message)
        else:
            error_message = f'Error in call_get() -> {api_url}: {r.status_code} {r.text}'
            if self.__logger:
                self.__logger.error(error_message)
            raise Exception(error_message)

        return retval

    def call_post_form_url_encoded(self, api_url: str, params: dict) -> str:
        """Generic Call Content Server API with POST method using Content-Type application/x-www-form-urlencoded.

        Args:
            api_url (str):
                The URL to be called. I.e. http://content-server/otcs/cs.exe

            params (dict):
                POST parameters as dictionary. I.e. { 'id': node_id } -> ?id=<node_id>

        Returns:
            str: JSON result of API call

        """
        error_message = ''
        retval = ''

        # do REST API call to CS
        auth_header = ''
        auth_ticket = ''
        if self.__login_type == LoginType.OTCS_TICKET:
            auth_header = 'OTCSTicket'
            auth_ticket = self.__ticket
        elif self.__login_type == LoginType.OTDS_TICKET:
            auth_header = 'OTDSTicket'
            auth_ticket = self.__ticket
        else:
            auth_header = 'Authorization'
            auth_ticket = f'Bearer {self.__ticket}'

        r = requests.post(url=api_url,
                         headers={'Content-Type': 'application/x-www-form-urlencoded', auth_header: auth_ticket,
                                  'User-Agent': self.__useragent}, data=params)

        if self.__logger:
            self.__pretty_print_POST(r.request)

        if r.ok:
            try:
                retval = r.text

                if self.__logger:
                    self.__logger.debug(f'-----------RESPONSE-----------\r\n{r.text}')

            except Exception as innerErr:
                error_message = f'Error in call_get() -> {api_url}: {innerErr}\n{r.text}'
                if self.__logger:
                    self.__logger.error(error_message)
                raise Exception(error_message)
        else:
            error_message = f'Error in call_get() -> {api_url}: {r.status_code} {r.text}'
            if self.__logger:
                self.__logger.error(error_message)
            raise Exception(error_message)

        return retval

    def node_get(self, base_url_cs: str, node_id: int, filter_properties: list, load_categories: bool, load_permissions: bool, load_classifications: bool) -> dict:
        """ Get Node Information - optionally include property filter, load category information, load permissions, load classifications.

        Args:
            base_url_cs (str):
                The URL to be called. I.e. http://content-server/otcs/cs.exe

            node_id (int):
                The Node ID to get the information

            filter_properties (list):
                The List to fetch only certain properties. I.e. ['id', 'name']

            load_categories (bool):
                Optionally load categories of node.

            load_permissions (bool):
                Optionally load permissions of node.

            load_classifications (bool):
                Optionally load classifications of node.

        Returns:
            dict: node information with structure: { 'properties': {}, 'categories': [], 'permissions': [], 'classifications': []}

        """
        retval = { 'properties': {}, 'categories': [], 'permissions': [], 'classifications': []}
        base_url = self.__check_url(base_url_cs)
        apiendpoint = f'api/v2/nodes/{node_id}'
        url = urllib.parse.urljoin(base_url, apiendpoint)

        params = {}
        if filter_properties and len(filter_properties) > 0:
            if not params.get('fields'):
                params['fields'] = []
            param = 'properties{' + ",".join(filter_properties) + '}'
            params['fields'].append(param)

        if load_categories:
            if not params.get('fields'):
                params['fields'] = []
            param = 'categories'
            params['fields'].append(param)

        if load_permissions:
            if not params.get('fields'):
                params['fields'] = []
            param = 'permissions'
            params['fields'].append(param)
            if not params.get('expand'):
                params['expand'] = []
            params['expand'].append('permissions{right_id}')


        res = self.call_get(url, params)

        jres = json.loads(res)

        if jres and jres.get('results', {}):
            item = jres.get('results', {})
            if item.get('data', {}) and item.get('data', {}).get('properties', {}):
                retval['properties'] = item["data"]["properties"]

                if load_categories:
                    retval['categories'] = item["data"].get('categories', [])

                if load_permissions:
                    retval['permissions'] = item["data"].get('permissions', [])

                if load_classifications:
                    retval['classifications'] = self.classifications_get(base_url_cs, node_id, ['data'])

        return retval

    def classifications_get(self, base_url_cs: str, node_id: int, filter_fields: list) -> list:
        """ Get Classifications of Node.

        Args:
            base_url_cs (str):
                The URL to be called. I.e. http://content-server/otcs/cs.exe

            node_id (int):
                The Node ID to get the information

            filter_fields (list):
                The List to fetch only certain properties. I.e. ['data']

        Returns:
            list: list of classifications

        """
        retval = []
        base_url = self.__check_url(base_url_cs)
        apiendpoint = f'api/v1/nodes/{node_id}/classifications'
        url = urllib.parse.urljoin(base_url, apiendpoint)

        params = {}
        if filter_fields and len(filter_fields) > 0:
            if not params.get('fields'):
                params['fields'] = []
            for field in filter_fields:
                params['fields'].append(field)

        res = self.call_get(url, params)

        jres = json.loads(res)

        if jres and jres.get('data', []):
            for item in jres.get('data', []):
                if filter_fields and len(filter_fields) > 0:
                    if item.get('cell_metadata'):
                        del item['cell_metadata']
                    retval.append(item)

        return retval

    # todo: paging
    def subnodes_get(self, base_url_cs: str, node_id: int, filter_properties: list, load_categories: bool, load_permissions: bool, load_classifications: bool) -> list:
        """ Get Sub Nodes - optionally include property filter, load category information, load permissions, load classifications.

        Args:
            base_url_cs (str):
                The URL to be called. I.e. http://content-server/otcs/cs.exe

            node_id (int):
                The Parent Node ID to load the Sub Nodes

            filter_properties (list):
                The List to fetch only certain properties. I.e. ['id', 'name']

            load_categories (bool):
                Optionally load categories of nodes.

            load_permissions (bool):
                Optionally load permissions of nodes.

            load_classifications (bool):
                Optionally load classifications of nodes.

        Returns:
            list: list of sub nodes with structure: [{ 'properties': {}, 'categories': [], 'permissions': [], 'classifications': []}]

        """
        retval = []
        base_url = self.__check_url(base_url_cs)
        apiendpoint = f'api/v2/nodes/{node_id}/nodes'
        url = urllib.parse.urljoin(base_url, apiendpoint)

        params = {}
        if filter_properties and len(filter_properties) > 0:
            if not params.get('fields'):
                params['fields'] = []
            param = 'properties{' + ",".join(filter_properties) + '}'
            params['fields'].append(param)

        if load_categories:
            if not params.get('fields'):
                params['fields'] = []
            param = 'categories'
            params['fields'].append(param)

        if load_permissions:
            if not params.get('fields'):
                params['fields'] = []
            param = 'permissions'
            params['fields'].append(param)
            if not params.get('expand'):
                params['expand'] = []
            params['expand'].append('permissions{right_id}')


        res = self.call_get(url, params)

        jres = json.loads(res)

        if jres and jres.get('results', []):
            for item in jres.get('results', []):
                if item.get('data', {}) and item.get('data', {}).get('properties', {}):
                    line = {'properties': item["data"]["properties"], 'categories': [], 'permissions': [], 'classifications': []}

                    if load_categories:
                        line['categories'] = item["data"].get('categories', [])

                    if load_permissions:
                        line['permissions'] = item["data"].get('permissions', [])

                    if load_classifications and item["data"]["properties"].get('id'):
                        line['classifications'] = self.classifications_get(base_url_cs, item["data"]["properties"].get('id'), ['data'])

                    retval.append(line)

        return retval

    def subnodes_filter(self, base_url_cs: str, node_id: int, filter_name: str, filter_container_only: bool, exact_match: bool) -> list:
        """ Filter for specific Sub Nodes.

        Args:
            base_url_cs (str):
                The URL to be called. I.e. http://content-server/otcs/cs.exe

            node_id (int):
                The Parent Node ID to load the Sub Nodes

            filter_name (str):
                Filter result on the provided name: I.e. "OTHCM_WS_Employee_Categories"

            filter_container_only (bool):
                Apply filter only on Containers (i.e. Folders).

            exact_match (bool):
                The name is matched fully -> filter out partial matches.

        Returns:
            list: list of sub nodes with structure: [{ 'properties': {'id', 'name'}}]

        """
        retval = []
        base_url = self.__check_url(base_url_cs)
        apiendpoint = f'api/v2/nodes/{node_id}/nodes'
        url = urllib.parse.urljoin(base_url, apiendpoint)

        params = { 'limit': 200, 'fields': ['properties{id,name}'], 'where_name': filter_name }

        if filter_container_only:
            params['where_type'] = -1

        res = self.call_get(url, params)

        jres = json.loads(res)

        if jres and jres.get('results', []):
            for item in jres.get('results', []):
                if item.get('data', {}) and item.get('data', {}).get('properties', {}):
                    if exact_match and item["data"]["properties"].get('name', '') == filter_name:
                        line = {'properties': item["data"]["properties"]}
                        retval.append(line)
                    elif not exact_match:
                        line = {'properties': item["data"]["properties"]}
                        retval.append(line)

        return retval

    def category_get(self, base_url_cs: str, node_id: int) -> dict:
        """ Get Classifications of Node.

        Args:
            base_url_cs (str):
                The URL to be called. I.e. http://content-server/otcs/cs.exe

            node_id (int):
                The Node ID to get the information

        Returns:
            dict: categories of node with structure: { 'properties': {'id', 'name', 'type', 'type_name'}, 'forms': []}

        """
        retval = { 'properties': {}, 'forms': []}
        base_url = self.__check_url(base_url_cs)
        apiendpoint = f'api/v2/nodes/{node_id}'
        url = urllib.parse.urljoin(base_url, apiendpoint)

        filter_properties = ['id', 'name', 'type', 'type_name']
        params = { }
        if filter_properties and len(filter_properties) > 0:
            if not params.get('fields'):
                params['fields'] = []
            param = 'properties{' + ",".join(filter_properties) + '}'
            params['fields'].append(param)

        res = self.call_get(url, params)

        jres = json.loads(res)

        if jres and jres.get('results', {}):
            item = jres.get('results', {})
            if item.get('data', {}) and item.get('data', {}).get('properties', {}):
                retval['properties'] = item["data"]["properties"]

                if item["data"]["properties"].get('type') and item["data"]["properties"].get('type') == 131:
                    retval['forms'] = self.specific_get(base_url_cs, node_id)
                else:
                    raise Exception(f'node_id {node_id} was expected to be a Category, but it is a {item["data"]["properties"].get('type_name')}')

        return retval

    def specific_get(self, base_url_cs: str, node_id: int) -> list:
        """ Get Specific information of Node. I.e. category definition of a category node

        Args:
            base_url_cs (str):
                The URL to be called. I.e. http://content-server/otcs/cs.exe

            node_id (int):
                The Node ID to get the information

        Returns:
            list: specific information of node

        """
        retval = []
        base_url = self.__check_url(base_url_cs)
        apiendpoint = 'api/v1/forms/nodes/properties/specific'
        url = urllib.parse.urljoin(base_url, apiendpoint)

        params = { 'id': node_id }
        res = self.call_get(url, params)

        jres = json.loads(res)

        if jres and jres.get('forms', []):
            for item in jres.get('forms', []):
                line = {'fields': {}, 'data': {}}
                if item.get('schema', {}):
                    line['fields'] = item["schema"]
                if item.get('data', {}):
                    line['data'] = item["data"]
                retval.append(line)

        return retval

    def category_get_mappings(self, base_url_cs: str, node_id: int) -> dict:
        """ Get Category mappings of the attributes with id and name as a dict object

        Args:
            base_url_cs (str):
                The URL to be called. I.e. http://content-server/otcs/cs.exe

            node_id (int):
                The Node ID of the category

        Returns:
            dict: dictionaries to map the ids and names of a category attributes with the structure: { 'main_name': '', 'main_id': 0, 'map_names': {}, 'map_ids': {}}

        """
        retval = { 'main_name': '', 'main_id': 0, 'map_names': {}, 'map_ids': {}}

        res = self.category_get(base_url_cs, node_id)

        category_name = res.get('properties', {}).get('name')
        category_id = res.get('properties', {}).get('id')

        retval['main_name'] = category_name
        retval['main_id'] = category_id

        for f in res.get('forms', []):
            if f.get('fields') and f.get('fields', {}).get('properties'):
                for prop in f['fields']['properties']:
                    if f['fields']['properties'][prop].get('title'):
                        field_id = f'{prop}'
                        field_name = f['fields']['properties'][prop].get('title')
                        retval['map_names'][field_name] = field_id
                        retval['map_ids'][field_id] = field_name
                        if f['fields']['properties'][prop].get('items') and f['fields']['properties'][prop].get('items', {}).get('properties'):
                            for subprop in f['fields']['properties'][prop]['items']['properties']:
                                if f['fields']['properties'][prop]['items']['properties'][subprop].get('title'):
                                    sub_field_id = f'{subprop}'
                                    sub_field_name = f['fields']['properties'][prop]['items']['properties'][subprop].get('title')
                                    retval['map_names'][f'{field_name}:{sub_field_name}'] = sub_field_id
                                    retval['map_ids'][sub_field_id] = f'{field_name}:{sub_field_name}'

        return retval

    def volumes_get(self, base_url_cs: str) -> list:
        """ Get Volumes of Content Server

        Args:
            base_url_cs (str):
                The URL to be called. I.e. http://content-server/otcs/cs.exe

        Returns:
            list: all available volumes of Content Server

        """
        retval = []
        base_url = self.__check_url(base_url_cs)
        apiendpoint = f'api/v2/volumes'
        url = urllib.parse.urljoin(base_url, apiendpoint)

        params = {'fields': ['properties{id,name}']}

        res = self.call_get(url, params)

        jres = json.loads(res)

        if jres and jres.get('results', []):
            for item in jres.get('results', []):
                if item.get('data', {}) and item.get('data', {}).get('properties', {}):
                    line = {'properties': item["data"]["properties"]}
                    retval.append(line)

        return retval

    def path_to_id(self, base_url_cs: str, cspath: str) -> dict:
        """ Get ID and Name of a Node by Path Information

        Args:
            base_url_cs (str):
                The URL to be called. I.e. http://content-server/otcs/cs.exe

            cspath (str):
                The path of the node. I.e. Content Server Categories:SuccessFactors:OTHCM_WS_Employee_Categories:Personal Information

        Returns:
            dict: ID and Name of the last node of the given path

        """
        retval = {}
        if cspath:
            vol_name = ''
            vol_id = 0
            path_lst = cspath.split(':')
            if len(path_lst) > 0:
                vol_name = path_lst[0]

            if vol_name:
                if not self.__volumes_hash or base_url_cs not in self.__volumes_hash:
                    res = self.volumes_get(base_url_cs)
                    self.__volumes_hash[base_url_cs] = {}
                    for item in res:
                        if item.get('properties', {}):
                            line = item["properties"]
                            self.__volumes_hash[base_url_cs][line["name"]] = line["id"]
                            self.__volumes_hash[base_url_cs][line["id"]] = line["name"]

                if vol_name in self.__volumes_hash[base_url_cs]:
                    vol_id = self.__volumes_hash[base_url_cs][vol_name]

            if vol_id > 0:
                if len(path_lst) > 1:
                    cnt = 1
                    parent_node = vol_id
                    for path_item in path_lst[1:]:
                        cnt += 1
                        if cnt < len(path_lst):
                            # container
                            itemres = self.subnodes_filter(base_url_cs, parent_node, path_item, True, True)
                            if len(itemres) > 0 and itemres[0].get('properties'):
                                parent_node = itemres[0]['properties']['id']
                            else:
                                raise Exception(f'Error in path_to_id() -> {path_item} not found in path.')
                        else:
                            # last item -> might be no container
                            itemres = self.subnodes_filter(base_url_cs, parent_node, path_item, False, True)
                            if len(itemres) > 0 and itemres[0].get('properties'):
                                parent_node = itemres[0]['properties']['id']
                                retval = {'id': itemres[0]['properties']['id'], 'name': itemres[0]['properties']['name']}
                            else:
                                raise Exception(f'Error in path_to_id() -> last item {path_item} not found in path.')
                else:
                    retval = {'id': vol_id, 'name': vol_name}

            else:
                raise Exception(f'Error in path_to_id() -> {vol_name} not found in volumes.')
        else:
            raise Exception('Error in path_to_id() -> please provide a valid path with the format: i.e. "Content Server Categories:SuccessFactors:OTHCM_WS_Employee_Categories:Personal Information"')

        return retval

    # todo: paging
    def search(self, base_url_cs: str, search_term: str, sub_type: int, location_node: int) -> list:
        """ Search for a node in Content Server

        Args:
            base_url_cs (str):
                The URL to be called. I.e. http://content-server/otcs/cs.exe

            search_term (str):
                The search term: I.e. Personal Information

            sub_type (int):
                The sub_type of the node to be searched for: 0=folder, 144=document, 131=category, ...

            location_node (int):
                The location (node_id) to be search in

        Returns:
            list: found nodes that correspond to the search criteria with structure: [{'id', 'name', 'parent_id'}]

        """
        retval = []
        base_url = self.__check_url(base_url_cs)
        apiendpoint = f'api/v2/search'
        url = urllib.parse.urljoin(base_url, apiendpoint)

        params = { 'body': json.dumps({ 'where': f'OTName: "{search_term.replace('"', '\"')}" and OTSubType: {sub_type} and OTLocation: {location_node}' })}

        res = self.call_post_form_url_encoded(url, params)

        jres = json.loads(res)

        if jres and jres.get('results', []):
            for item in jres.get('results', []):
                if item.get('data', {}) and item.get('data', {}).get('properties', {}):
                    line = {'id': item["data"]["properties"].get("id"), 'name': item["data"]["properties"].get("name"), 'parent_id': item["data"]["properties"].get("parent_id")}
                    retval.append(line)

        return retval

    # todo: implement
    def download(self):
        pass

    def upload(self):
        pass
