__author__ = "Philipp Egger"
__copyright__ = "Copyright (C) 2025, Philipp Egger"
__credits__ = ["Philipp Egger"]
__maintainer__ = "Philipp Egger"
__email__ = "philipp.egger@handel-it.com"

import base64
import logging
import requests
import enum
import urllib.parse
import json
import os
from datetime import datetime

class LoginType(enum.Enum):
    OTCS_TICKET = enum.auto()
    OTDS_TICKET = enum.auto()
    OTDS_BEARER = enum.auto()

class CSRestAPI:
    """ Do Login and get OTCSTicket, OTDSTicket or Bearer Token """
    __logger: logging.Logger
    __useragent = 'Chrome xECM'
    __base_url = ''
    __ticket = ''
    __usr = ''
    __pwd = ''
    __verify_ssl = True
    __login_type: LoginType
    __volumes_hash = {}
    __category_hash = {}

    def __init__(
        self,
        login_type: LoginType,
        login_url: str,
        user_or_client_id: str,
        pw_or_client_secret: str,
        verify_ssl: bool,
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

            self.__verify_ssl = verify_ssl

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
                                   'Content-Type': 'application/x-www-form-urlencoded'}, verify=self.__verify_ssl)

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
                                   'Content-Type': 'application/json;charset=utf-8'}, verify=self.__verify_ssl)

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
                                   'Content-Type': 'application/x-www-form-urlencoded'}, auth=(client_id, client_secret), verify=self.__verify_ssl)

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

    def ping(self, base_url_cs: str) -> dict:
        """Ping Content Server API with GET method.

        Args:
            base_url_cs (str):
                The URL to be called. I.e. http://content-server/otcs/cs.exe

        Returns:
            dict: Result of API call. I.e. {'rest_api': [{'build': 2, 'href': 'api/v1', 'version': 1}]}

        """
        error_message = ''
        retval = ''

        # do REST API call to CS
        base_url = self.__check_url(base_url_cs)
        apiendpoint = f'api/v1/ping'
        url = urllib.parse.urljoin(base_url, apiendpoint)

        r = requests.get(url=url, headers={'Content-Type': 'application/json', 'User-Agent': self.__useragent}, verify=self.__verify_ssl)

        if self.__logger:
            self.__pretty_print_GET(r.request)

        if r.ok:
            try:
                retval = json.loads(r.text)

                if self.__logger:
                    self.__logger.debug(f'-----------RESPONSE-----------\r\n{r.text}')

            except Exception as innerErr:
                error_message = f'Error in ping() -> {url}: {innerErr}\n{r.text}'
                if self.__logger:
                    self.__logger.error(error_message)
                raise Exception(error_message)
        else:
            error_message = f'Error in ping() -> {url}: {r.status_code} {r.text}'
            if self.__logger:
                self.__logger.error(error_message)
            raise Exception(error_message)

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
                                  'User-Agent': self.__useragent}, params=params, verify=self.__verify_ssl)

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

        r = requests.post(url=api_url, headers={'Content-Type': 'application/x-www-form-urlencoded', auth_header: auth_ticket, 'User-Agent': self.__useragent}, data=params, verify=self.__verify_ssl)

        if self.__logger:
            self.__pretty_print_POST(r.request)

        if r.ok:
            try:
                retval = r.text

                if self.__logger:
                    self.__logger.debug(f'-----------RESPONSE-----------\r\n{r.text}')

            except Exception as innerErr:
                error_message = f'Error in call_post_form_url_encoded() -> {api_url}: {innerErr}\n{r.text}'
                if self.__logger:
                    self.__logger.error(error_message)
                raise Exception(error_message)
        else:
            error_message = f'Error in call_post_form_url_encoded() -> {api_url}: {r.status_code} {r.text}'
            if self.__logger:
                self.__logger.error(error_message)
            raise Exception(error_message)

        return retval

    def call_post_form_data(self, api_url: str, params: dict, files: dict) -> str:
        """Generic Call Content Server API with POST method using Content-Type application/form-data.

        Args:
            api_url (str):
                The URL to be called. I.e. http://content-server/otcs/cs.exe

            params (dict):
                POST parameters as dictionary. I.e. { 'id': node_id }

            files (dict):
                FILE parameter as dictionary. I.e. {'file': (remote_filename, open(os.path.join(local_folder, local_filename), 'rb'), 'application/octet-stream')}

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

        r = requests.post(url=api_url, headers={auth_header: auth_ticket, 'User-Agent': self.__useragent}, data=params, files=files, verify=self.__verify_ssl)

        if self.__logger:
            self.__pretty_print_POST(r.request)

        if r.ok:
            try:
                retval = r.text

                if self.__logger:
                    self.__logger.debug(f'-----------RESPONSE-----------\r\n{r.text}')

            except Exception as innerErr:
                error_message = f'Error in call_post_form_data() -> {api_url}: {innerErr}\n{r.text}'
                if self.__logger:
                    self.__logger.error(error_message)
                raise Exception(error_message)
        else:
            error_message = f'Error in call_post_form_data() -> {api_url}: {r.status_code} {r.text}'
            if self.__logger:
                self.__logger.error(error_message)
            raise Exception(error_message)

        return retval

    def call_put(self, api_url: str, params: dict) -> str:
        """Generic Call Content Server API with PUT method.

        Args:
            api_url (str):
                The URL to be called. I.e. http://content-server/otcs/cs.exe

            params (dict):
                POST parameters as dictionary. I.e. { 'id': node_id }

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

        r = requests.put(url=api_url, headers={auth_header: auth_ticket, 'User-Agent': self.__useragent}, data=params, verify=self.__verify_ssl)

        if self.__logger:
            self.__pretty_print_POST(r.request)

        if r.ok:
            try:
                retval = r.text

                if self.__logger:
                    self.__logger.debug(f'-----------RESPONSE-----------\r\n{r.text}')

            except Exception as innerErr:
                error_message = f'Error in call_put() -> {api_url}: {innerErr}\n{r.text}'
                if self.__logger:
                    self.__logger.error(error_message)
                raise Exception(error_message)
        else:
            error_message = f'Error in call_put() -> {api_url}: {r.status_code} {r.text}'
            if self.__logger:
                self.__logger.error(error_message)
            raise Exception(error_message)

        return retval

    def call_delete(self, api_url: str) -> str:
        """Generic Call Content Server API with DELETE method.

        Args:
            api_url (str):
                The URL to be called. I.e. http://content-server/otcs/cs.exe

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

        r = requests.delete(url=api_url, headers={'Content-Type': 'application/json', auth_header: auth_ticket, 'User-Agent': self.__useragent}, verify=self.__verify_ssl)

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

    def server_info(self, base_url_cs: str) -> dict:
        """ Get Server Information and Configuration.

        Args:
            base_url_cs (str):
                The URL to be called. I.e. http://content-server/otcs/cs.exe

        Returns:
            dict: information about server: { 'mobile': {}, 'server': {}, 'sessions': {}, 'smartUIConfig': {}, 'viewer': {}}

        """
        if self.__logger:
            self.__logger.debug(f'server_info() start: {locals()}')
        retval = {}
        base_url = self.__check_url(base_url_cs)
        apiendpoint = f'api/v1/serverinfo'
        url = urllib.parse.urljoin(base_url, apiendpoint)

        params = {}

        res = self.call_get(url, params)

        retval = json.loads(res)

        if self.__logger:
            self.__logger.debug(f'server_info() finished: {retval}')

        return retval

    def node_get(self, base_url_cs: str, node_id: int, filter_properties: list, load_categories: bool, load_permissions: bool, load_classifications: bool) -> dict:
        """ Get Node Information - optionally include property filter, load category information, load permissions, load classifications.

        Args:
            base_url_cs (str):
                The URL to be called. I.e. http://content-server/otcs/cs.exe

            node_id (int):
                The Node ID to get the information

            filter_properties (list):
                The List to fetch only certain properties. I.e. ['id', 'name'] or ['id', 'name', 'type', 'type_name', 'name_multilingual', 'description_multilingual'] or [] for all properties

            load_categories (bool):
                Optionally load categories of node.

            load_permissions (bool):
                Optionally load permissions of node.

            load_classifications (bool):
                Optionally load classifications of node.

        Returns:
            dict: node information with structure: { 'properties': {}, 'categories': [], 'permissions': [], 'classifications': []}

        """
        if self.__logger:
            self.__logger.debug(f'node_get() start: {locals()}')
        retval = { 'properties': {}, 'categories': [], 'permissions': { 'owner': {}, 'group': {}, 'public': {}, 'custom': [] }, 'classifications': []}
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
                    for perms in item["data"].get('permissions', []):
                        if perms.get('type', ''):
                            if perms['type'] == 'owner':
                                retval['permissions']['owner'] = perms
                            elif perms['type'] == 'group':
                                retval['permissions']['group'] = perms
                            elif perms['type'] == 'public':
                                retval['permissions']['public'] = perms
                            elif perms['type'] == 'custom':
                                retval['permissions']['custom'].append(perms)
                            else:
                                raise Exception(f"Error in node_get() - permission type {perms['type']} is not supported.")

                if load_classifications:
                    try:
                        retval['classifications'] = self.node_classifications_get(base_url_cs, node_id, ['data'])
                    except Exception as innerErr:
                        error_message = f'Error in node_get() while getting classifications -> {innerErr}'
                        if self.__logger:
                            self.__logger.error(error_message)

        if self.__logger:
            self.__logger.debug(f'node_get() finished: {retval}')

        return retval

    def node_create(self, base_url_cs: str, parent_id: int, type_id: int, node_name:str, node_description: str, multi_names: dict, multi_descriptions: dict) -> int:
        """ Create a Node.

        Args:
            base_url_cs (str):
                The URL to be called. I.e. http://content-server/otcs/cs.exe

            parent_id (int):
                The parent id of container in which the node is created.

            type_id (int):
                The type id of the new node. I.e. 0 for a folder

            node_name (str):
                The name of the new node.

            node_description (str):
                The description of the new node.

            multi_names (dict):
                The names in different languages of the new node. I.e. { 'en': 'name en', 'de': 'name de' }

            multi_descriptions (dict):
                The descriptions in different languages of the new node. I.e. { 'en': 'desc en', 'de': 'desc de' }

        Returns:
            int: the new node id of the uploaded document

        """
        if self.__logger:
            self.__logger.debug(f'node_create() start: {locals()}')
        retval = -1
        base_url = self.__check_url(base_url_cs)
        apiendpoint = f'api/v2/nodes'
        url = urllib.parse.urljoin(base_url, apiendpoint)

        data = {'type': type_id, 'parent_id': parent_id, 'name': node_name}
        if node_description:
            data['description'] = node_description
        if multi_names:
            data['name_multilingual'] = multi_names
        if multi_descriptions:
            data['description_multilingual'] = multi_descriptions

        params = {'body': json.dumps(data)}

        res = self.call_post_form_url_encoded(url, params)

        jres = json.loads(res)

        if jres and jres.get('results', {}) and jres['results'].get('data', {}) and  jres['results']['data'].get('properties', {}):
            retval = jres['results']['data']['properties'].get('id', -1)

        if self.__logger:
            self.__logger.debug(f'node_create() finished: {retval}')

        return retval

    def node_update(self, base_url_cs: str, node_id: int, new_parent_id: int, new_name: str, new_description: str, new_multi_names: dict, new_multi_descriptions: dict, new_categories_when_moved: dict) -> int:
        """ Generic update of a Node.

        Args:
            base_url_cs (str):
                The URL to be called. I.e. http://content-server/otcs/cs.exe

            node_id (int):
                The node which is updated.

            new_parent_id (int):
                Optional: if set then the node is moved to this new target.

            new_name (str):
                Optional: if set then the name of the node is renamed.

            new_description (str):
                Optional: if set then the description of the node is changed.

            new_multi_names (dict):
                Optional: if set then the names in different languages of the node are renamed. I.e. { 'en': 'name en', 'de': 'name de' }

            new_multi_descriptions (dict):
                Optional: if set then the descriptions in different languages of the node are changed. I.e. { 'en': 'desc en', 'de': 'desc de' }

            new_categories_when_moved (dict):
                Optional: if set then the categories of the node are changed when the node is moved to a new location. I.e. {"6228_2":"hello"} or {"inheritance":0} (selecting ORIGINAL categories inheritance when moved) or {"inheritance":1, "6228_2":"hello"} (selecting DESTINATION categories inheritance and applying a custom value to 6228_2 when moved) or {"inheritance":2, "9830_1":{}, "6228_1":{}} (selecting MERGED categories inheritance and applying default values to 9830_1 and 6228_1)

        Returns:
            int: the node id of the updated node

        """
        if self.__logger:
            self.__logger.debug(f'node_update() start: {locals()}')
        retval = -1
        base_url = self.__check_url(base_url_cs)
        apiendpoint = f'api/v2/nodes/{node_id}'
        url = urllib.parse.urljoin(base_url, apiendpoint)

        data = {}
        if new_parent_id and new_parent_id > 0:
            data['parent_id'] = new_parent_id
        if new_name:
            data['name'] = new_name
        if new_description:
            data['description'] = new_description
        if new_multi_names:
            data['name_multilingual'] = new_multi_names
        if new_multi_descriptions:
            data['description_multilingual'] = new_multi_descriptions
        if new_categories_when_moved:
            if not new_parent_id or not new_parent_id > 0:
                raise Exception(f'Error in node_update(): provide a new parent_id ({new_parent_id}) when applying categories.')
            data['roles'] = { 'categories': new_categories_when_moved }

        params = {'body': json.dumps(data)}

        res = self.call_put(url, params)

        jres = json.loads(res)

        if jres and jres.get('results', {}) and jres['results'].get('data', {}) and  jres['results']['data'].get('properties', {}):
            retval = jres['results']['data']['properties'].get('id', -1)

        if self.__logger:
            self.__logger.debug(f'node_update() finished: {retval}')

        return retval

    def node_update_name(self, base_url_cs: str, node_id: int, new_name: str, new_description: str, new_multi_names: dict, new_multi_descriptions: dict) -> int:
        """ Update the names and descriptions of a Node.

        Args:
            base_url_cs (str):
                The URL to be called. I.e. http://content-server/otcs/cs.exe

            node_id (int):
                The node which is updated.

            new_name (str):
                Optional: if set then the name of the node is renamed.

            new_description (str):
                Optional: if set then the description of the node is changed.

            new_multi_names (dict):
                Optional: if set then the names in different languages of the node are renamed. I.e. { 'en': 'name en', 'de': 'name de' }

            new_multi_descriptions (dict):
                Optional: if set then the descriptions in different languages of the node are changed. I.e. { 'en': 'desc en', 'de': 'desc de' }

        Returns:
            int: the node id of the updated node

        """

        if self.__logger:
            self.__logger.debug(f'node_update_name() start: {locals()}')

        retval = self.node_update(base_url_cs, node_id, 0, new_name, new_description, new_multi_names, new_multi_descriptions, {})

        if self.__logger:
            self.__logger.debug(f'node_update_name() finished: {retval}')

        return retval

    def node_move(self, base_url_cs: str, node_id: int, new_parent_id: int) -> int:
        """ Move a Node.

        Args:
            base_url_cs (str):
                The URL to be called. I.e. http://content-server/otcs/cs.exe

            node_id (int):
                The node which is updated.

            new_parent_id (int):
                The node is moved to this new target.

        Returns:
            int: the node id of the updated node

        """
        if self.__logger:
            self.__logger.debug(f'node_move() start: {locals()}')

        retval = self.node_update(base_url_cs, node_id, new_parent_id, '', '', {}, {}, {})

        if self.__logger:
            self.__logger.debug(f'node_move() finished: {retval}')

        return retval

    def node_move_and_apply_category(self, base_url_cs: str, node_id: int, new_parent_id: int, new_categories_when_moved: dict) -> int:
        """ Move a Node.

        Args:
            base_url_cs (str):
                The URL to be called. I.e. http://content-server/otcs/cs.exe

            node_id (int):
                The node which is updated.

            new_parent_id (int):
                The node is moved to this new target.

            new_categories_when_moved (dict):
                The categories of the node are changed when the node is moved to a new location. I.e. {"6228_2":"hello"} or {"inheritance":0} (selecting ORIGINAL categories inheritance when moved) or {"inheritance":1, "6228_2":"hello"} (selecting DESTINATION categories inheritance and applying a custom value to 6228_2 when moved) or {"inheritance":2, "9830_1":{}, "6228_1":{}} (selecting MERGED categories inheritance and applying default values to 9830_1 and 6228_1)

        Returns:
            int: the node id of the updated node

        """
        if self.__logger:
            self.__logger.debug(f'node_move_and_apply_category() start: {locals()}')

        retval = self.node_update(base_url_cs, node_id, new_parent_id, '', '', {}, {}, new_categories_when_moved)

        if self.__logger:
            self.__logger.debug(f'node_move_and_apply_category() finished: {retval}')

        return retval

    def node_delete(self, base_url_cs: str, node_id: int):
        """ Create a Node.

        Args:
            base_url_cs (str):
                The URL to be called. I.e. http://content-server/otcs/cs.exe

            node_id (int):
                The node id to be deleted.

        Returns:
            int: the new node id of the uploaded document

        """
        if self.__logger:
            self.__logger.debug(f'node_delete() start: {locals()}')
        retval = {}
        base_url = self.__check_url(base_url_cs)
        apiendpoint = f'api/v2/nodes/{node_id}'
        url = urllib.parse.urljoin(base_url, apiendpoint)

        res = self.call_delete(url)

        jres = json.loads(res)

        if jres and jres.get('results', {}):
            retval = jres.get('results', {})

        if self.__logger:
            self.__logger.debug(f'node_delete() finished: {retval}')

        return retval

    def node_download_file(self, base_url_cs: str, node_id: int, node_version: str, local_folder: str, local_filename: str) -> dict:
        """ Download Node Content into a Local File.

        Args:
            base_url_cs (str):
                The URL to be called. I.e. http://content-server/otcs/cs.exe

            node_id (int):
                The Node ID to get the information

            node_version (str):
                Optionally the version of the node

            local_folder (str):
                The local path to store the file.

            local_filename (str):
                The file name of the document.

        Returns:
            dict: result of download with structure {'message', 'file_size', 'location'}

        """
        if self.__logger:
            self.__logger.debug(f'node_download_file() start: {locals()}')
        retval = { 'message': 'ok' }
        base_url = self.__check_url(base_url_cs)
        apiendpoint = f'api/v2/nodes/{node_id}'
        if node_version != '':
            apiendpoint += f'/versions/{node_version}'
        apiendpoint += '/content'
        url = urllib.parse.urljoin(base_url, apiendpoint)

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

        # download content into local file
        try:
            with requests.get(url=url, headers={'Content-Type': 'application/json', auth_header: auth_ticket, 'User-Agent': self.__useragent}, stream=True, verify=self.__verify_ssl) as r:
                r.raise_for_status()
                file_size = 0
                if self.__logger:
                    self.__pretty_print_GET(r.request)
                with open(os.path.join(local_folder, local_filename), 'wb') as f:
                    for chunk in r.iter_content(chunk_size=8192):
                        # If you have chunk encoded response uncomment if
                        # and set chunk_size parameter to None.
                        # if chunk:
                        file_size += len(chunk)
                        f.write(chunk)

                retval['file_size'] = file_size
                retval['location'] = os.path.join(local_folder, local_filename)

                if self.__logger:
                    self.__logger.debug(f'-----------RESPONSE-----------\r\n{retval}')

        except Exception as innerErr:
            error_message = f'Error in node_download() -> {url}: {innerErr}\n{r.text}'
            if self.__logger:
                self.__logger.error(error_message)
            raise Exception(error_message)

        if self.__logger:
            self.__logger.debug(f'node_download_file() finished: {retval}')

        return retval

    def node_download_bytes(self, base_url_cs: str, node_id: int, node_version: str) -> dict:
        """ Download Node Content as Byte Array.

        Args:
            base_url_cs (str):
                The URL to be called. I.e. http://content-server/otcs/cs.exe

            node_id (int):
                The Node ID to get the information

            node_version (str):
                Optionally the version of the node

        Returns:
            dict: result of download with structure {'message', 'file_size', 'base64' }

        """
        if self.__logger:
            self.__logger.debug(f'node_download_bytes() start: {locals()}')
        retval = { 'message': 'ok' }
        base_url = self.__check_url(base_url_cs)
        apiendpoint = f'api/v2/nodes/{node_id}'
        if node_version != '':
            apiendpoint += f'/versions/{node_version}'
        apiendpoint += '/content'
        url = urllib.parse.urljoin(base_url, apiendpoint)

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

        # download content into local file
        try:
            with requests.get(url=url, headers={'Content-Type': 'application/json', auth_header: auth_ticket, 'User-Agent': self.__useragent}, stream=True, verify=self.__verify_ssl) as r:
                r.raise_for_status()
                file_size = 0
                if self.__logger:
                    self.__pretty_print_GET(r.request)

                b = bytearray()
                for chunk in r.iter_content(chunk_size=8192):
                    # If you have chunk encoded response uncomment if
                    # and set chunk_size parameter to None.
                    # if chunk:
                    file_size += len(chunk)
                    b.extend(chunk)

                retval['file_size'] = file_size
                retval['base64'] = base64.b64encode(b).decode()

                if self.__logger:
                    self.__logger.debug(f'-----------RESPONSE-----------\r\n{retval}')

        except Exception as innerErr:
            error_message = f'Error in node_download() -> {url}: {innerErr}\n{r.text}'
            if self.__logger:
                self.__logger.error(error_message)
            raise Exception(error_message)

        if self.__logger:
            self.__logger.debug(f'node_download_bytes() finished: {retval}')
        return retval

    def node_upload_file(self, base_url_cs: str, parent_id: int, local_folder: str, local_filename: str, remote_filename: str, categories: dict) -> int:
        """ Upload Document into Content Server from a Local File.

        Args:
            base_url_cs (str):
                The URL to be called. I.e. http://content-server/otcs/cs.exe

            parent_id (int):
                The parent id of container to which the document is uploaded.

            local_folder (str):
                The local path to store the file.

            local_filename (str):
                The local file name of the document.

            remote_filename (str):
                The remote file name of the document.

            categories (dict):
                Optional categories of the document. I.e. { "30724_2": "2023-03-20" }

        Returns:
            int: the new node id of the uploaded document

        """
        if self.__logger:
            self.__logger.debug(f'node_upload_file() start: {locals()}')
        retval = -1
        base_url = self.__check_url(base_url_cs)
        apiendpoint = f'api/v2/nodes'
        url = urllib.parse.urljoin(base_url, apiendpoint)

        data = { 'type': 144, 'parent_id': parent_id, 'name': remote_filename }
        if categories:
            data['roles'] = { 'categories': categories }
        params = { 'body' : json.dumps(data) }

        files = {'file': (remote_filename, open(os.path.join(local_folder, local_filename), 'rb'), 'application/octet-stream')}

        res = self.call_post_form_data(url, params, files)

        jres = json.loads(res)

        if jres and jres.get('results', {}) and jres['results'].get('data', {}) and  jres['results']['data'].get('properties', {}):
            retval = jres['results']['data']['properties'].get('id', -1)

        if self.__logger:
            self.__logger.debug(f'node_upload_file() finished: {retval}')

        return retval

    def node_upload_bytes(self, base_url_cs: str, parent_id: int, content_bytes: bytes, remote_filename: str, categories: dict) -> int:
        """ Upload Document into Content Server as Byte Array.

        Args:
            base_url_cs (str):
                The URL to be called. I.e. http://content-server/otcs/cs.exe

            parent_id (int):
                The parent id of container to which the document is uploaded.

            content_bytes (bytes):
                The bytearray containing the file's content.

            remote_filename (str):
                The remote file name of the document.

            categories (dict):
                Optional categories of the document. I.e. { "30724_2": "2023-03-20" }

        Returns:
            int: the new node id of the uploaded document

        """
        if self.__logger:
            self.__logger.debug(f'node_upload_bytes() start: {locals()}')
        retval = -1
        base_url = self.__check_url(base_url_cs)
        apiendpoint = f'api/v2/nodes'
        url = urllib.parse.urljoin(base_url, apiendpoint)

        data = { 'type': 144, 'parent_id': parent_id, 'name': remote_filename }
        if categories:
            data['roles'] = { 'categories': categories }
        params = { 'body' : json.dumps(data) }

        files = {'file': (remote_filename, content_bytes, 'application/octet-stream')}

        res = self.call_post_form_data(url, params, files)

        jres = json.loads(res)

        if jres and jres.get('results', {}) and jres['results'].get('data', {}) and  jres['results']['data'].get('properties', {}):
            retval = jres['results']['data']['properties'].get('id', -1)

        if self.__logger:
            self.__logger.debug(f'node_upload_bytes() finished: {retval}')

        return retval

    def node_category_add(self, base_url_cs: str, node_id: int, category: dict) -> int:
        """ Apply Category to a Node.

        Args:
            base_url_cs (str):
                The URL to be called. I.e. http://content-server/otcs/cs.exe

            node_id (int):
                The node id to which the category is applied.

            category (str):
                The category values. I.e. {"category_id":9830} (apply category and use default values) or {"category_id":9830,"9830_2":"new value"} (apply category and set a value) or {"category_id":9830,"9830_3_2_4":["","","new value"]} (apply category and set values in a set of a text field)

        Returns:
            int: the node id of the changed node

        """
        if self.__logger:
            self.__logger.debug(f'node_category_add() start: {locals()}')
        retval = -1
        base_url = self.__check_url(base_url_cs)
        apiendpoint = f'api/v2/nodes/{node_id}/categories'
        url = urllib.parse.urljoin(base_url, apiendpoint)

        params = {'body': json.dumps(category)}

        res = self.call_post_form_url_encoded(url, params)

        jres = json.loads(res)

        if jres:
            retval = node_id

        if self.__logger:
            self.__logger.debug(f'node_category_add() finished: {retval}')

        return retval

    def node_category_update(self, base_url_cs: str, node_id: int, category_id: int, category: dict) -> int:
        """ Update Category values of a Node.

        Args:
            base_url_cs (str):
                The URL to be called. I.e. http://content-server/otcs/cs.exe

            node_id (int):
                The node id to which the category is applied.

            category_id (int):
                The category id to which the values are applied.

            category (str):
                The category values. I.e. {"category_id":9830} (apply category and use default values) or {"category_id":9830,"9830_2":"new value"} (apply category and set a value) or {"category_id":9830,"9830_3_2_4":["","","new value"]} (apply category and set values in a set of a text field)

        Returns:
            int: the node id of the changed node

        """
        if self.__logger:
            self.__logger.debug(f'node_category_update() start: {locals()}')
        retval = -1
        base_url = self.__check_url(base_url_cs)
        apiendpoint = f'api/v2/nodes/{node_id}/categories/{category_id}'
        url = urllib.parse.urljoin(base_url, apiendpoint)

        params = {'body': json.dumps(category)}

        res = self.call_put(url, params)

        jres = json.loads(res)

        if jres:
            retval = node_id

        if self.__logger:
            self.__logger.debug(f'node_category_update() finished: {retval}')

        return retval

    def node_category_delete(self, base_url_cs: str, node_id: int, category_id: int) -> int:
        """ Delete a Category from a Node.

        Args:
            base_url_cs (str):
                The URL to be called. I.e. http://content-server/otcs/cs.exe

            node_id (int):
                The node id to which the category is applied.

            category_id (int):
                The category id which is removed from the node.

        Returns:
            int: the node id of the changed node

        """
        if self.__logger:
            self.__logger.debug(f'node_category_delete() start: {locals()}')
        retval = -1
        base_url = self.__check_url(base_url_cs)
        apiendpoint = f'api/v2/nodes/{node_id}/categories/{category_id}'
        url = urllib.parse.urljoin(base_url, apiendpoint)

        res = self.call_delete(url)

        jres = json.loads(res)

        if jres:
            retval = node_id

        if self.__logger:
            self.__logger.debug(f'node_category_delete() finished: {retval}')

        return retval

    def node_classifications_get(self, base_url_cs: str, node_id: int, filter_fields: list) -> list:
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
        if self.__logger:
            self.__logger.debug(f'node_classifications_get() start: {locals()}')
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

        if self.__logger:
            self.__logger.debug(f'node_classifications_get() finished: {retval}')

        return retval

    def node_classifications_apply(self, base_url_cs: str, node_id: int, apply_to_subitems: bool, classification_ids: list) -> int:
        """ Apply (Update/Delete) Classifications to Node.

        Args:
            base_url_cs (str):
                The URL to be called. I.e. http://content-server/otcs/cs.exe

            node_id (int):
                The Node ID to get the information

            apply_to_subitems (bool):
                If set, apply the classifications to all sub-items.

            classification_ids (list):
                The List of classifications to be added to the node. I.e. [120571,120570]

        Returns:
            list: list of classifications

        """
        if self.__logger:
            self.__logger.debug(f'node_classifications_apply() start: {locals()}')
        retval = -1
        base_url = self.__check_url(base_url_cs)
        apiendpoint = f'api/v1/nodes/{node_id}/classifications'
        url = urllib.parse.urljoin(base_url, apiendpoint)

        data = { 'apply_to_sub_items': apply_to_subitems, 'class_id': classification_ids}
        params = { 'body': json.dumps(data) }

        res = self.call_post_form_url_encoded(url, params)

        jres = json.loads(res)

        retval = node_id

        if self.__logger:
            self.__logger.debug(f'node_classifications_apply() finished: {retval}')

        return retval

    def subnodes_get(self, base_url_cs: str, node_id: int, filter_properties: list, load_categories: bool, load_permissions: bool, load_classifications: bool, page: int) -> dict:
        """ Get Sub Nodes - optionally include property filter, load category information, load permissions, load classifications.

        Args:
            base_url_cs (str):
                The URL to be called. I.e. http://content-server/otcs/cs.exe

            node_id (int):
                The Parent Node ID to load the Sub Nodes

            filter_properties (list):
                The List to fetch only certain properties. I.e. ['id', 'name'] or ['id', 'name', 'type', 'type_name', 'name_multilingual', 'description_multilingual'] or [] for all properties

            load_categories (bool):
                Optionally load categories of nodes.

            load_permissions (bool):
                Optionally load permissions of nodes.

            load_classifications (bool):
                Optionally load classifications of nodes.

            page (int):
                The page number to fetch in the results

        Returns:
            dict: list of sub nodes with structure: { 'results': [{ 'properties': {}, 'categories': [], 'permissions': [], 'classifications': []}], 'page_total': 0 }

        """
        if self.__logger:
            self.__logger.debug(f'subnodes_get() start: {locals()}')
        retval = { 'results': [], 'page_total': 0 }
        base_url = self.__check_url(base_url_cs)
        apiendpoint = f'api/v2/nodes/{node_id}/nodes'
        url = urllib.parse.urljoin(base_url, apiendpoint)

        limit = 200

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
            limit = 20

        if load_permissions:
            if not params.get('fields'):
                params['fields'] = []
            param = 'permissions'
            params['fields'].append(param)
            if not params.get('expand'):
                params['expand'] = []
            params['expand'].append('permissions{right_id}')
            limit = 20

        if load_classifications:
            limit = 10

        params['limit'] = limit
        if page and page > 0:
            params['page'] = page

        res = self.call_get(url, params)

        jres = json.loads(res)

        if jres and jres.get('results', []):
            for item in jres.get('results', []):
                if item.get('data', {}) and item.get('data', {}).get('properties', {}):
                    line = {'properties': item["data"]["properties"], 'categories': [], 'permissions': { 'owner': {}, 'group': {}, 'public': {}, 'custom': [] }, 'classifications': []}

                    if load_categories:
                        line['categories'] = item["data"].get('categories', [])

                    if load_permissions:
                        for perms in item["data"].get('permissions', []):
                            if perms.get('type', ''):
                                if perms['type'] == 'owner':
                                    line['permissions']['owner'] = perms
                                elif perms['type'] == 'group':
                                    line['permissions']['group'] = perms
                                elif perms['type'] == 'public':
                                    line['permissions']['public'] = perms
                                elif perms['type'] == 'custom':
                                    line['permissions']['custom'].append(perms)
                                else:
                                    raise Exception(f"Error in subnodes_get() - permission type {perms['type']} is not supported.")

                    if load_classifications and item["data"]["properties"].get('id'):
                        try:
                            line['classifications'] = self.node_classifications_get(base_url_cs, item["data"]["properties"].get('id'), ['data'])
                        except Exception as innerErr:
                            error_message = f'Error in subnodes_get() while getting classifications -> {item["data"]["properties"]} -> {innerErr}'
                            if self.__logger:
                                self.__logger.error(error_message)

                    retval['results'].append(line)


            if jres.get('collection', {}) and jres['collection'].get('paging', {}) and jres['collection']['paging'].get('page_total'):
                retval['page_total'] = jres['collection']['paging']['page_total']

        if self.__logger:
            self.__logger.debug(f'subnodes_get() finished: {retval}')

        return retval

    def subnodes_filter(self, base_url_cs: str, node_id: int, filter_name: str, filter_container_only: bool, exact_match: bool) -> list:
        """ Filter for specific Sub Nodes. Max 200 entries are returned.

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
        if self.__logger:
            self.__logger.debug(f'subnodes_filter() start: {locals()}')
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

        if self.__logger:
            self.__logger.debug(f'subnodes_filter() finished: {retval}')

        return retval

    def category_definition_get(self, base_url_cs: str, node_id: int) -> dict:
        """ Get Classifications of Node.

        Args:
            base_url_cs (str):
                The URL to be called. I.e. http://content-server/otcs/cs.exe

            node_id (int):
                The Node ID to get the information

        Returns:
            dict: categories of node with structure: { 'properties': {'id', 'name', 'type', 'type_name'}, 'forms': []}

        """
        if self.__logger:
            self.__logger.debug(f'category_definition_get() start: {locals()}')
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

        if self.__logger:
            self.__logger.debug(f'category_definition_get() finished: {retval}')

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
        if self.__logger:
            self.__logger.debug(f'specific_get() start: {locals()}')
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

        if self.__logger:
            self.__logger.debug(f'specific_get() finished: {retval}')

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
        if self.__logger:
            self.__logger.debug(f'category_get_mappings() start: {locals()}')
        retval = { 'main_name': '', 'main_id': 0, 'map_names': {}, 'map_ids': {}}

        res = self.category_definition_get(base_url_cs, node_id)

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

        if self.__logger:
            self.__logger.debug(f'category_get_mappings() finished: {retval}')

        return retval

    def volumes_get(self, base_url_cs: str) -> list:
        """ Get Volumes of Content Server

        Args:
            base_url_cs (str):
                The URL to be called. I.e. http://content-server/otcs/cs.exe

        Returns:
            list: all available volumes of Content Server

        """
        if self.__logger:
            self.__logger.debug(f'volumes_get() start: {locals()}')
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

        if self.__logger:
            self.__logger.debug(f'volumes_get() finished: {retval}')

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
        if self.__logger:
            self.__logger.debug(f'path_to_id() start: {locals()}')
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

        if self.__logger:
            self.__logger.debug(f'path_to_id() finished: {retval}')

        return retval

    def member_get(self, base_url_cs: str, group_id: int) -> dict:
        """ Get Information on a Group Member

        Args:
            base_url_cs (str):
                The URL to be called. I.e. http://content-server/otcs/cs.exe

            group_id (int):
                The Group ID.

        Returns:
            dict: Details of the Member Group

        """
        if self.__logger:
            self.__logger.debug(f'member_get() start: {locals()}')
        retval = []
        base_url = self.__check_url(base_url_cs)
        apiendpoint = f'api/v1/members/{group_id}'
        url = urllib.parse.urljoin(base_url, apiendpoint)

        params = { 'expand': 'member' }

        res = self.call_get(url, params)

        jres = json.loads(res)

        retval = jres.get('data', {})

        if self.__logger:
            self.__logger.debug(f'member_get() finished: {retval}')

        return retval

    def search(self, base_url_cs: str, search_term: str, sub_type: int, location_node: int, page: int) -> dict:
        """ Search in Content Server

        Args:
            base_url_cs (str):
                The URL to be called. I.e. http://content-server/otcs/cs.exe

            search_term (str):
                The search term: I.e. Personal Information

            sub_type (int):
                The sub_type of the node to be searched for: 0=folder, 144=document, 131=category, ...

            location_node (int):
                The location (node_id) to be search in

            page (int):
                The page number to fetch in the results

        Returns:
            dict: found nodes that correspond to the search criteria with structure: { 'results': [{'id', 'name', 'parent_id'}], 'page_total': 0 }

        """
        if self.__logger:
            self.__logger.debug(f'search() start: {locals()}')
        retval = { 'results': [], 'page_total': 0 }
        base_url = self.__check_url(base_url_cs)
        apiendpoint = f'api/v2/search'
        url = urllib.parse.urljoin(base_url, apiendpoint)

        params = { 'body': json.dumps({ 'limit': 100, 'where': f'OTName: "{search_term.replace('"', '\"')}" and OTSubType: {sub_type} and OTLocation: {location_node}' })}

        if page and page > 0:
            params['page'] = page

        res = self.call_post_form_url_encoded(url, params)

        jres = json.loads(res)

        if jres and jres.get('results', []):
            for item in jres.get('results', []):
                if item.get('data', {}) and item.get('data', {}).get('properties', {}):
                    line = {'id': item["data"]["properties"].get("id"), 'name': item["data"]["properties"].get("name"), 'parent_id': item["data"]["properties"].get("parent_id")}
                    retval['results'].append(line)

            if jres.get('collection', {}) and jres['collection'].get('paging', {}) and jres['collection']['paging'].get('page_total'):
                retval['page_total'] = jres['collection']['paging']['page_total']

        if self.__logger:
            self.__logger.debug(f'search() finished: {retval}')
        return retval

    def category_attribute_id_get(self, base_url_cs: str, category_path: str, attribute_name: str) -> dict:
        """ Get ID and Name of a Node by Path Information

        Args:
            base_url_cs (str):
                The URL to be called. I.e. http://content-server/otcs/cs.exe

            category_path (str):
                The path of the category. I.e. Content Server Categories:SuccessFactors:OTHCM_WS_Employee_Categories:Personal Information

            attribute_name (str):
                The attribute name inside the category. I.e. 'User ID' or 'Personnel Number'

        Returns:
            dict: ID, Name of the category and Attribute Key of the attribute_name. I.e. {'category_id': 30643, 'category_name': 'Personal Information', 'attribute_key': '30643_26', 'attribute_name': 'User ID'}

        """
        if self.__logger:
            self.__logger.debug(f'category_attribute_id_get() start: {locals()}')
        retval = {}
        if not self.__category_hash or base_url_cs not in self.__category_hash:
            self.__category_hash[base_url_cs] = { 'category_path_to_id': {} }

        if category_path not in self.__category_hash[base_url_cs]['category_path_to_id']:
            res = self.path_to_id(base_url_cs, category_path)
            if res and res.get('id', 0):
                cat_id = res.get('id', 0)
                self.__category_hash[base_url_cs]['category_path_to_id'][category_path] = { 'category_id': cat_id, 'category_name': res.get('name', ''), 'attribute_map': {}}
                res = self.category_get_mappings(base_url_cs, res.get('id', 0))
                if res and res.get('map_names', {}):
                    self.__category_hash[base_url_cs]['category_path_to_id'][category_path]['attribute_map'] = res.get('map_names', {})
                else:
                    raise Exception(f'Error in category_attribute_id_get() -> {category_path} not found. ID = {cat_id}.')
            else:
                raise Exception(f'Error in category_attribute_id_get() -> {category_path} not found. Call to path_to_id() returned an empty result.')

        cat_id = self.__category_hash[base_url_cs]['category_path_to_id'][category_path]['category_id']
        retval['category_id'] = cat_id
        retval['category_name'] = self.__category_hash[base_url_cs]['category_path_to_id'][category_path]['category_name']
        if attribute_name in self.__category_hash[base_url_cs]['category_path_to_id'][category_path]['attribute_map']:
            retval['attribute_key'] = self.__category_hash[base_url_cs]['category_path_to_id'][category_path]['attribute_map'][attribute_name]
            retval['attribute_name'] = attribute_name
        else:
            raise Exception(f'Error in category_attribute_id_get() -> attribute "{attribute_name}" not found in ({cat_id}) {category_path}.')

        if self.__logger:
            self.__logger.debug(f'category_attribute_id_get() finished: {retval}')

        return retval

    def smartdoctypes_get_all(self, base_url_cs: str) -> list:
        """ Get all Smart Document Types of Content Server

        Args:
            base_url_cs (str):
                The URL to be called. I.e. http://content-server/otcs/cs.exe

        Returns:
            list: all available Smart Document Types of Content Server

        """
        if self.__logger:
            self.__logger.debug(f'smartdoctypes_get_all() start: {locals()}')
        retval = []
        base_url = self.__check_url(base_url_cs)
        apiendpoint = f'api/v2/smartdocumenttypes'
        url = urllib.parse.urljoin(base_url, apiendpoint)

        params = {}

        res = self.call_get(url, params)

        jres = json.loads(res)

        if jres and jres.get('results', {}) and jres['results'].get('data', []):
            retval = jres['results'].get('data', [])

        if self.__logger:
            self.__logger.debug(f'smartdoctypes_get_all() finished: {retval}')

        return retval

    def smartdoctypes_rules_get(self, base_url_cs: str, smartdoctype_id: int) -> list:
        """ Get Rules of a specific Smart Document Type

        Args:
            base_url_cs (str):
                The URL to be called. I.e. http://content-server/otcs/cs.exe

            smartdoctype_id (int):
                The Smart Document Type ID to get the details.

        Returns:
            list: Rules for the Smart Document Type

        """
        if self.__logger:
            self.__logger.debug(f'smartdoctypes_rules_get() start: {locals()}')
        retval = []
        base_url = self.__check_url(base_url_cs)
        apiendpoint = f'api/v2/smartdocumenttypes/smartdocumenttypedetails'
        url = urllib.parse.urljoin(base_url, apiendpoint)

        params = { 'smart_document_type_id': smartdoctype_id }

        res = self.call_get(url, params)

        jres = json.loads(res)

        if jres and jres.get('results', {}) and jres['results'].get('data', []):
            retval = jres['results'].get('data', [])

        if self.__logger:
            self.__logger.debug(f'smartdoctypes_rules_get() finished: {retval}')

        return retval

    def smartdoctype_rule_detail_get(self, base_url_cs: str, rule_id: int) -> list:
        """ Get the details of a specific Smart Document Type Rule

        Args:
            base_url_cs (str):
                The URL to be called. I.e. http://content-server/otcs/cs.exe

            rule_id (int):
                The Rule ID to get the details.

        Returns:
            list: Get Details of the Smart Document Type Rule

        """
        if self.__logger:
            self.__logger.debug(f'smartdoctype_rule_detail_get() start: {locals()}')
        retval = []
        base_url = self.__check_url(base_url_cs)
        apiendpoint = f'api/v2/smartdocumenttypes/rules/{rule_id}/bots'
        url = urllib.parse.urljoin(base_url, apiendpoint)

        params = {}

        res = self.call_get(url, params)

        jres = json.loads(res)

        if jres and jres.get('results', {}) and jres['results'].get('forms', []):
            retval = jres['results'].get('forms', [])

        if self.__logger:
            self.__logger.debug(f'smartdoctype_rule_detail_get() finished: {retval}')

        return retval

    def smartdoctype_add(self, base_url_cs: str, parent_id: int, classification_id: int, smartdoctype_name: str) -> int:
        """ Add a new Smart Document Type

        Args:
            base_url_cs (str):
                The URL to be called. I.e. http://content-server/otcs/cs.exe

            parent_id (int):
                The Parent ID of the container in which the Smart Document Type is created.

            classification_id (int):
                The Classification ID the Smart Document Type is referred.

            smartdoctype_name (str):
                The Name of the Smart Document Type.

        Returns:
            int: the ID of the Smart Document Type

        """
        if self.__logger:
            self.__logger.debug(f'smartdoctype_add() start: {locals()}')
        retval = -1
        base_url = self.__check_url(base_url_cs)
        apiendpoint = f'api/v1/nodes'
        url = urllib.parse.urljoin(base_url, apiendpoint)
        data = {'type': 877, 'type_name': 'Add Smart Document Type', 'container': True, 'parent_id': parent_id, 'inactive': True, 'classificationId': classification_id, 'anchorTitle': '', 'anchorTitleShort': smartdoctype_name, 'name': smartdoctype_name, 'classification': classification_id}
        params = {'body': json.dumps(data)}

        res = self.call_post_form_url_encoded(url, params)

        jres = json.loads(res)
        retval = jres.get('id', -1)

        if self.__logger:
            self.__logger.debug(f'smartdoctype_add() finished: {retval}')

        return retval

    def smartdoctype_workspacetemplate_add(self, base_url_cs: str, smartdoctype_id: int, classification_id: int, workspacetemplate_id: int) -> dict:
        """ Add a new Smart Document Type

        Args:
            base_url_cs (str):
                The URL to be called. I.e. http://content-server/otcs/cs.exe

            smartdoctype_id (int):
                The Node ID of the Smart Document Type.

            classification_id (int):
                The Classification ID the Smart Document Type is referred.

            workspacetemplate_id (int):
                The Workspace Template ID.

        Returns:
            dict: the result of the action. I.e. {'is_othcm_template': True, 'ok': True, 'rule_id': 11, 'statusCode': 200}

        """
        if self.__logger:
            self.__logger.debug(f'smartdoctype_workspacetemplate_add() start: {locals()}')
        retval = {}
        base_url = self.__check_url(base_url_cs)
        apiendpoint = f'api/v2/smartdocumenttypes/rules'
        url = urllib.parse.urljoin(base_url, apiendpoint)

        params = { 'smart_document_type_id': smartdoctype_id, 'classification_id': classification_id, 'template_id': workspacetemplate_id}

        res = self.call_post_form_data(url, params, {})

        jres = json.loads(res)
        retval = jres.get('results', {})

        if self.__logger:
            self.__logger.debug(f'smartdoctype_workspacetemplate_add() finished: {retval}')

        return retval

    def smartdoctype_rule_context_save(self, base_url_cs: str, rule_id: int, based_on_category_id: int, location_id: int) -> dict:
        """ Add/update the Set Context tab for a Smart Document Type Rule

        Args:
            base_url_cs (str):
                The URL to be called. I.e. http://content-server/otcs/cs.exe

            rule_id (int):
                The Rule ID to update.

            based_on_category_id (int):
                The Category ID for the document metadata. I.e. default category can be found under: Content Server Categories:Document Types:Document Type Details

            location_id (int):
                The Target Location ID in the workspace template.

        Returns:
            dict: the result of the action. I.e. {'ok': True, 'statusCode': 200, 'updatedAttributeIds': [2], 'updatedAttributeNames': ['Date of Origin']}

        """
        if self.__logger:
            self.__logger.debug(f'smartdoctype_rule_context_save() start: {locals()}')
        retval = {}
        base_url = self.__check_url(base_url_cs)
        apiendpoint = f'api/v2/smartdocumenttypes/rules/{rule_id}/bots/context'
        url = urllib.parse.urljoin(base_url, apiendpoint)

        data = {'location': location_id, 'based_on_category': str(based_on_category_id), 'rule_expression': {'expressionText': '', 'expressionData': [], 'expressionDataKey': ''}, 'bot_action': 'update'}
        params = {'body': json.dumps(data)}

        res = self.call_put(url, params)

        jres = json.loads(res)

        retval = jres.get('results', {})

        if self.__logger:
            self.__logger.debug(f'smartdoctype_rule_context_save() finished: {retval}')

        return retval

    def smartdoctype_rule_mandatory_save(self, base_url_cs: str, rule_id: int, is_mandatory: bool, bot_action: str) -> dict:
        """ Add/update the Make Mandatory tab for a Smart Document Type Rule

        Args:
            base_url_cs (str):
                The URL to be called. I.e. http://content-server/otcs/cs.exe

            rule_id (int):
                The Rule ID to update.

            is_mandatory (bool):
                The mandatory flag to be set.

            bot_action (str):
                The action: use 'add' to create the tab or 'update' to update the values.

        Returns:
            dict: the result of the action. I.e. {'ok': True, 'statusCode': 200}

        """
        if self.__logger:
            self.__logger.debug(f'smartdoctype_rule_mandatory_save() start: {locals()}')
        retval = {}
        base_url = self.__check_url(base_url_cs)
        apiendpoint = f'api/v2/smartdocumenttypes/rules/{rule_id}/bots/makemandatory'
        url = urllib.parse.urljoin(base_url, apiendpoint)

        data = {'mandatory': is_mandatory, 'bot_action': bot_action}
        params = {'body': json.dumps(data)}

        res = self.call_put(url, params)

        jres = json.loads(res)

        retval = jres.get('results', {})

        if self.__logger:
            self.__logger.debug(f'smartdoctype_rule_mandatory_save() finished: {retval}')

        return retval

    def smartdoctype_rule_mandatory_delete(self, base_url_cs: str, rule_id: int) -> dict:
        """ Delete the Make Mandatory tab from a Smart Document Type Rule

        Args:
            base_url_cs (str):
                The URL to be called. I.e. http://content-server/otcs/cs.exe

            rule_id (int):
                The Rule ID to update.

        Returns:
            dict: the result of the action. I.e. {'ok': True, 'statusCode': 200}

        """
        if self.__logger:
            self.__logger.debug(f'smartdoctype_rule_mandatory_delete() start: {locals()}')
        retval = {}
        base_url = self.__check_url(base_url_cs)
        apiendpoint = f'api/v2/smartdocumenttypes/rules/{rule_id}/bots/makemandatory'
        url = urllib.parse.urljoin(base_url, apiendpoint)

        res = self.call_delete(url)

        jres = json.loads(res)

        retval = jres.get('results', {})

        if self.__logger:
            self.__logger.debug(f'smartdoctype_rule_mandatory_delete() finished: {retval}')

        return retval

    def smartdoctype_rule_documentexpiration_save(self, base_url_cs: str, rule_id: int, validity_required: bool, based_on_attribute: int, num_years: int, num_months: int, bot_action: str) -> dict:
        """ Add/update the Check Document Expiration tab for a Smart Document Type Rule

        Args:
            base_url_cs (str):
                The URL to be called. I.e. http://content-server/otcs/cs.exe

            rule_id (int):
                The Rule ID to update.

            validity_required (bool):
                Is Validity Check Reqired.

            based_on_attribute (int):
                Attribute Number for i.e. Date Of Origin to calculate the expiration date. I.e. 2 if default "Category Document Type" Details is used.

            num_years (int):
                Number of years validity.

            num_months (int):
                Number of months validity.

            bot_action (str):
                The action: use 'add' to create the tab or 'update' to update the values.

        Returns:
            dict: the result of the action. I.e. {'ok': True, 'statusCode': 200, 'updatedAttributeIds': [2], 'updatedAttributeNames': ['Date of Origin']}

        """
        if self.__logger:
            self.__logger.debug(f'smartdoctype_rule_documentexpiration_save() start: {locals()}')
        retval = {}
        base_url = self.__check_url(base_url_cs)
        apiendpoint = f'api/v2/smartdocumenttypes/rules/{rule_id}/bots/completenesscheck'
        url = urllib.parse.urljoin(base_url, apiendpoint)

        data = {'validity_required': validity_required, 'based_on_attribute': str(based_on_attribute), 'validity_years': num_years, 'validity_months': str(num_months), 'bot_action': bot_action}
        params = {'body': json.dumps(data)}

        res = self.call_put(url, params)

        jres = json.loads(res)

        retval = jres.get('results', {})

        if self.__logger:
            self.__logger.debug(f'smartdoctype_rule_documentexpiration_save() finished: {retval}')

        return retval

    def smartdoctype_rule_documentexpiration_delete(self, base_url_cs: str, rule_id: int) -> dict:
        """ Delete the Check Document Expiration tab from a Smart Document Type Rule

        Args:
            base_url_cs (str):
                The URL to be called. I.e. http://content-server/otcs/cs.exe

            rule_id (int):
                The Rule ID to update.

        Returns:
            dict: the result of the action. I.e. {'ok': True, 'statusCode': 200}

        """
        if self.__logger:
            self.__logger.debug(f'smartdoctype_rule_documentexpiration_delete() start: {locals()}')
        retval = {}
        base_url = self.__check_url(base_url_cs)
        apiendpoint = f'api/v2/smartdocumenttypes/rules/{rule_id}/bots/completenesscheck'
        url = urllib.parse.urljoin(base_url, apiendpoint)

        res = self.call_delete(url)

        jres = json.loads(res)

        retval = jres.get('results', {})

        if self.__logger:
            self.__logger.debug(f'smartdoctype_rule_documentexpiration_delete() finished: {retval}')

        return retval

    def smartdoctype_rule_generatedocument_save(self, base_url_cs: str, rule_id: int, is_doc_gen: bool, bot_action: str) -> dict:
        """ Add/update the Generate Document tab for a Smart Document Type Rule

        Args:
            base_url_cs (str):
                The URL to be called. I.e. http://content-server/otcs/cs.exe

            rule_id (int):
                The Rule ID to update.

            is_doc_gen (bool):
                The document generation flag to be set.

            bot_action (str):
                The action: use 'add' to create the tab or 'update' to update the values.

        Returns:
            dict: the result of the action. I.e. {'ok': True, 'statusCode': 200}

        """
        if self.__logger:
            self.__logger.debug(f'smartdoctype_rule_generatedocument_save() start: {locals()}')
        retval = {}
        base_url = self.__check_url(base_url_cs)
        apiendpoint = f'api/v2/smartdocumenttypes/rules/{rule_id}/bots/createdocument'
        url = urllib.parse.urljoin(base_url, apiendpoint)

        data = {'docgen': is_doc_gen, 'bot_action': bot_action}
        params = {'body': json.dumps(data)}

        res = self.call_put(url, params)

        jres = json.loads(res)

        retval = jres.get('results', {})

        if self.__logger:
            self.__logger.debug(f'smartdoctype_rule_generatedocument_save() finished: {retval}')

        return retval

    def smartdoctype_rule_generatedocument_delete(self, base_url_cs: str, rule_id: int) -> dict:
        """ Delete the Generate Document tab from a Smart Document Type Rule

        Args:
            base_url_cs (str):
                The URL to be called. I.e. http://content-server/otcs/cs.exe

            rule_id (int):
                The Rule ID to update.

        Returns:
            dict: the result of the action. I.e. {'ok': True, 'statusCode': 200}

        """
        if self.__logger:
            self.__logger.debug(f'smartdoctype_rule_generatedocument_delete() start: {locals()}')
        retval = {}
        base_url = self.__check_url(base_url_cs)
        apiendpoint = f'api/v2/smartdocumenttypes/rules/{rule_id}/bots/createdocument'
        url = urllib.parse.urljoin(base_url, apiendpoint)

        res = self.call_delete(url)

        jres = json.loads(res)

        retval = jres.get('results', {})

        if self.__logger:
            self.__logger.debug(f'smartdoctype_rule_generatedocument_delete() finished: {retval}')

        return retval

    def smartdoctype_rule_allowupload_save(self, base_url_cs: str, rule_id: int, members: list, bot_action: str) -> dict:
        """ Add/update the Allow Upload tab for a Smart Document Type Rule

        Args:
            base_url_cs (str):
                The URL to be called. I.e. http://content-server/otcs/cs.exe

            rule_id (int):
                The Rule ID to update.

            members (list):
                The list of groups to be set.

            bot_action (str):
                The action: use 'add' to create the tab or 'update' to update the values.

        Returns:
            dict: the result of the action. I.e. {'ok': True, 'statusCode': 200}

        """
        if self.__logger:
            self.__logger.debug(f'smartdoctype_rule_allowupload_save() start: {locals()}')
        retval = {}
        base_url = self.__check_url(base_url_cs)
        apiendpoint = f'api/v2/smartdocumenttypes/rules/{rule_id}/bots/uploadcontrol'
        url = urllib.parse.urljoin(base_url, apiendpoint)

        members_data = []
        for grp in members:
            grp_details = self.member_get(base_url_cs, grp)
            memb = grp_details.copy()
            memb['data'] = {}
            memb['data']['properties'] = grp_details.copy()
            members_data.append(memb)


        data = {'member': members, 'bot_action': bot_action, 'membersData': members_data}
        params = {'body': json.dumps(data)}

        res = self.call_put(url, params)

        jres = json.loads(res)

        retval = jres.get('results', {})

        if self.__logger:
            self.__logger.debug(f'smartdoctype_rule_allowupload_save() finished: {retval}')

        return retval

    def smartdoctype_rule_allowupload_delete(self, base_url_cs: str, rule_id: int) -> dict:
        """ Delete the Allow Upload tab from a Smart Document Type Rule

        Args:
            base_url_cs (str):
                The URL to be called. I.e. http://content-server/otcs/cs.exe

            rule_id (int):
                The Rule ID to update.

        Returns:
            dict: the result of the action. I.e. {'ok': True, 'statusCode': 200}

        """
        if self.__logger:
            self.__logger.debug(f'smartdoctype_rule_allowupload_delete() start: {locals()}')
        retval = {}
        base_url = self.__check_url(base_url_cs)
        apiendpoint = f'api/v2/smartdocumenttypes/rules/{rule_id}/bots/uploadcontrol'
        url = urllib.parse.urljoin(base_url, apiendpoint)

        res = self.call_delete(url)

        jres = json.loads(res)

        retval = jres.get('results', {})

        if self.__logger:
            self.__logger.debug(f'smartdoctype_rule_allowupload_delete() finished: {retval}')

        return retval

    def smartdoctype_rule_uploadapproval_save(self, base_url_cs: str, rule_id: int, review_required: bool, workflow_id: int, wf_roles: list, bot_action: str) -> dict:
        """ Add/update the Upload with Approval tab for a Smart Document Type Rule. An additional Workflow Map is required with the Map > General > Role Implementation being set to Map Based.

        Args:
            base_url_cs (str):
                The URL to be called. I.e. http://content-server/otcs/cs.exe

            rule_id (int):
                The Rule ID to update.

            review_required (bool):
                The Review Required flag to be set.

            workflow_id (int):
                The Workflow ID of the Approval Flow.

            wf_roles (list):
                The list of workflow roles to be set. I.e. [{'wfrole': 'Approver', 'member': 2001 }]

            bot_action (str):
                The action: use 'add' to create the tab or 'update' to update the values.

        Returns:
            dict: the result of the action. I.e. {'ok': True, 'statusCode': 200}

        """
        if self.__logger:
            self.__logger.debug(f'smartdoctype_rule_uploadapproval_save() start: {locals()}')
        retval = {}
        base_url = self.__check_url(base_url_cs)
        apiendpoint = f'api/v2/smartdocumenttypes/rules/{rule_id}/bots/uploadwithapproval'
        url = urllib.parse.urljoin(base_url, apiendpoint)

        role_hash = {}
        for role in wf_roles:
            if role['wfrole'] not in role_hash:
                role_hash[role['wfrole']] = []
            role_hash[role['wfrole']].append(role['member'])

        role_mappings = []
        for role_key in role_hash:
            role_map = { 'workflowRole': role_key, 'member': 0, 'membersData': [] }

            for group_id in role_hash[role_key]:
                # role_map['member'].append(group_id)
                role_map['member'] = group_id
                grp_details = self.member_get(base_url_cs, group_id)
                memb = grp_details.copy()
                memb['data'] = {}
                memb['data']['properties'] = grp_details.copy()
                role_map['membersData'].append(memb)

            role_mappings.append(role_map)

        data = {'review_required': review_required, 'review_workflow_location': workflow_id, 'role_mappings': role_mappings, 'bot_action': bot_action}
        params = {'body': json.dumps(data)}

        res = self.call_put(url, params)

        jres = json.loads(res)

        retval = jres.get('results', {})

        if self.__logger:
            self.__logger.debug(f'smartdoctype_rule_uploadapproval_save() finished: {retval}')

        return retval

    def smartdoctype_rule_uploadapproval_delete(self, base_url_cs: str, rule_id: int) -> dict:
        """ Delete the Upload with Approval tab from a Smart Document Type Rule

        Args:
            base_url_cs (str):
                The URL to be called. I.e. http://content-server/otcs/cs.exe

            rule_id (int):
                The Rule ID to update.

        Returns:
            dict: the result of the action. I.e. {'ok': True, 'statusCode': 200}

        """
        if self.__logger:
            self.__logger.debug(f'smartdoctype_rule_uploadapproval_delete() start: {locals()}')
        retval = {}
        base_url = self.__check_url(base_url_cs)
        apiendpoint = f'api/v2/smartdocumenttypes/rules/{rule_id}/bots/uploadwithapproval'
        url = urllib.parse.urljoin(base_url, apiendpoint)

        res = self.call_delete(url)

        jres = json.loads(res)

        retval = jres.get('results', {})

        if self.__logger:
            self.__logger.debug(f'smartdoctype_rule_uploadapproval_delete() finished: {retval}')

        return retval

    def businessworkspace_search(self, base_url_cs: str, logical_system: str, bo_type: str, bo_id: str, page: int) -> dict:
        """ Search for a Business Workspace by Business Object Type and ID

        Args:
            base_url_cs (str):
                The URL to be called. I.e. http://content-server/otcs/cs.exe

            logical_system (str):
                The Logical System customized under the Connections to Business Applications (External Systems). I.e. SuccessFactors

            bo_type (str):
                The Business Object Type. I.e. sfsf:user or BUS1065

            bo_id (str):
                The Business Object ID. I.e. 2100000

            page (int):
                The page number to fetch in the results

        Returns:
             dict: found businessworkspaces that correspond to the search criteria with structure: { 'results': [{'id', 'name', 'parent_id'}], 'page_total': 0 }

        """
        if self.__logger:
            self.__logger.debug(f'businessworkspace_search() start: {locals()}')
        retval = { 'results': [], 'page_total': 0 }
        base_url = self.__check_url(base_url_cs)
        apiendpoint = f'api/v2/businessworkspaces'
        url = urllib.parse.urljoin(base_url, apiendpoint)

        params = { 'where_ext_system_id': logical_system, 'where_bo_type': bo_type, 'where_bo_id': bo_id, 'expanded_view': 0, 'page': page, 'limit': 200 }

        res = self.call_get(url, params)

        jres = json.loads(res)

        if jres and jres.get('results', []):
            for item in jres.get('results', []):
                if item.get('data', {}) and item.get('data', {}).get('properties', {}):
                    line = {'id': item["data"]["properties"].get("id"), 'name': item["data"]["properties"].get("name"), 'parent_id': item["data"]["properties"].get("parent_id")}
                    retval['results'].append(line)

            if jres.get('paging', {}):
                retval['page_total'] = jres['paging'].get('page_total', 0)

        if self.__logger:
            self.__logger.debug(f'businessworkspace_search() finished: {retval}')

        return retval

    def businessworkspace_smartdoctypes_get(self, base_url_cs: str, bws_id: int) -> list:
        """ Get available Smart Document Types of Business Workspace

        Args:
            base_url_cs (str):
                The URL to be called. I.e. http://content-server/otcs/cs.exe

            bws_id (str):
                The Node ID of the Business Workspace

        Returns:
             list: available Smart Document Types of the requested Business Workspace: { 'results': [{'id', 'name', 'parent_id'}], 'page_total': 0 }

        """
        if self.__logger:
            self.__logger.debug(f'businessworkspace_smartdoctypes_get() start: {locals()}')
        retval = []
        base_url = self.__check_url(base_url_cs)
        apiendpoint = f'api/v2/businessworkspaces/{bws_id}/doctypes'
        url = urllib.parse.urljoin(base_url, apiendpoint)

        params = { 'skip_validation': False, 'document_type_rule': True, 'document_generation_only': False, 'sort_by': 'DocumentType', 'parent_id': bws_id, 'filter_by_location': True }

        res = self.call_get(url, params)

        jres = json.loads(res)

        if jres and jres.get('results', []):
            for item in jres.get('results', []):
                if item.get('data', {}) and item.get('data', {}).get('properties', {}):
                    line = {'classification_id': item["data"]["properties"].get("classification_id"), 'classification_name': item["data"]["properties"].get("classification_name"), 'classification_description': item["data"]["properties"].get("classification_description"), 'category_id': item["data"]["properties"].get("category_id"), 'location': item["data"]["properties"].get("location"), 'document_generation': item["data"]["properties"].get("document_generation"), 'required': item["data"]["properties"].get("required"), 'template_id': item["data"]["properties"].get("template_id")}
                    retval.append(line)

        if self.__logger:
            self.__logger.debug(f'businessworkspace_smartdoctypes_get() finished: {retval}')

        return retval

    def businessworkspace_categorydefinition_for_upload_get(self, base_url_cs: str, bws_id: int, category_id: int) -> list:
        """ Get Category Form for Uploading File into Business Workspace

        Args:
            base_url_cs (str):
                The URL to be called. I.e. http://content-server/otcs/cs.exe

            bws_id (str):
                The Node ID of the Business Workspace

            category_id (str):
                The Node ID of the Category which is applied. Get it from businessworkspace_smartdoctypes_get()

        Returns:
             list: form fields of the category definition: { 'results': [{'id', 'name', 'parent_id'}], 'page_total': 0 }

        """
        if self.__logger:
            self.__logger.debug(f'businessworkspace_categorydefinition_for_upload_get() start: {locals()}')
        retval = []
        base_url = self.__check_url(base_url_cs)
        apiendpoint = f'api/v1/forms/nodes/categories/create'
        url = urllib.parse.urljoin(base_url, apiendpoint)

        params = { 'id': bws_id, 'category_id': category_id }

        res = self.call_get(url, params)

        jres = json.loads(res)

        if jres and jres.get('forms', []):
            retval = jres.get('forms', [])

        if self.__logger:
            self.__logger.debug(f'businessworkspace_categorydefinition_for_upload_get() finished: {retval}')

        return retval

    def businessworkspace_hr_upload_file_depricated(self, base_url_cs: str, logical_system: str, bo_type: str, bo_id: str, local_folder: str, local_filename: str, remote_filename: str, document_type: str, date_of_origin: datetime) -> int:
        """ Upload Document into HR workspace from a Local File.

        Args:
            base_url_cs (str):
                The URL to be called. I.e. http://content-server/otcs/cs.exe

            logical_system (str):
                The Logical System customized under the Connections to Business Applications (External Systems). I.e. SuccessFactors

            bo_type (str):
                The Business Object Type. I.e. sfsf:user or BUS1065

            bo_id (str):
                The Business Object ID. I.e. 2100000

            local_folder (str):
                The local path to store the file.

            local_filename (str):
                The local file name of the document.

            remote_filename (str):
                The remote file name of the document.

            document_type (str):
                The document type (name of classification) of the document. I.e. 'Application Document'

            date_of_origin (datetime):
                The date of origin of the document.

        Returns:
            int: the new node id of the uploaded document

        """
        if self.__logger:
            self.__logger.debug(f'businessworkspace_hr_upload_file_depricated() start: {locals()}')
        retval = -1
        base_url = self.__check_url(base_url_cs)
        apiendpoint = f'api/v2/businessobjects/{logical_system}/{bo_type}/{bo_id}/hrdocuments'
        url = urllib.parse.urljoin(base_url, apiendpoint)

        params = { 'doc_type': document_type, 'date_of_origin': date_of_origin.isoformat() }

        files = {'file': (remote_filename, open(os.path.join(local_folder, local_filename), 'rb'), 'application/octet-stream')}

        res = self.call_post_form_data(url, params, files)

        jres = json.loads(res)

        if jres and jres.get('results', {}):
            retval = jres['results'].get('nodeID', -1)

        if self.__logger:
            self.__logger.debug(f'businessworkspace_hr_upload_file_depricated() finished: {retval}')

        return retval

    def businessworkspace_hr_upload_bytes_depricated(self, base_url_cs: str, logical_system: str, bo_type: str, bo_id: str, content_bytes: bytes, remote_filename: str, document_type: str, date_of_origin: datetime) -> int:
        """ Upload Document into HR workspace as Byte Array.

        Args:
            base_url_cs (str):
                The URL to be called. I.e. http://content-server/otcs/cs.exe

            logical_system (str):
                The Logical System customized under the Connections to Business Applications (External Systems). I.e. SuccessFactors

            bo_type (str):
                The Business Object Type. I.e. sfsf:user or BUS1065

            bo_id (str):
                The Business Object ID. I.e. 2100000

            content_bytes (bytes):
                The bytearray containing the file's content.

            remote_filename (str):
                The remote file name of the document.

            document_type (str):
                The document type (name of classification) of the document. I.e. 'Application Document'

            date_of_origin (datetime):
                The date of origin of the document.

        Returns:
            int: the new node id of the uploaded document

        """
        if self.__logger:
            self.__logger.debug(f'businessworkspace_hr_upload_bytes_depricated() start: {locals()}')
        retval = -1
        base_url = self.__check_url(base_url_cs)
        apiendpoint = f'api/v2/businessobjects/{logical_system}/{bo_type}/{bo_id}/hrdocuments'
        url = urllib.parse.urljoin(base_url, apiendpoint)

        params = { 'doc_type': document_type, 'date_of_origin': date_of_origin.isoformat() }

        files = {'file': (remote_filename, content_bytes, 'application/octet-stream')}

        res = self.call_post_form_data(url, params, files)

        jres = json.loads(res)

        if jres and jres.get('results', {}):
            retval = jres['results'].get('nodeID', -1)

        if self.__logger:
            self.__logger.debug(f'businessworkspace_hr_upload_bytes_depricated() finished: {retval}')

        return retval

    def businessworkspace_hr_upload_file(self, base_url_cs: str, bws_id: int, local_folder: str, local_filename: str, remote_filename: str, classification_id: int, category_id: int, category: dict) -> int:
        """ Upload Document into HR workspace from a Local File.

        Args:
            base_url_cs (str):
                The URL to be called. I.e. http://content-server/otcs/cs.exe

            bws_id (str):
                The NodeID of the Business Workspace.

            local_folder (str):
                The local path to store the file.

            local_filename (str):
                The local file name of the document.

            remote_filename (str):
                The remote file name of the document.

            classification_id (int):
                The Node ID of the document type (ID of classification) of the document.

            category_id (int):
                The Node ID of the category (containing the Date Of Origin) of the document.

            category (dict):
                The category containing usually the date of origin of the document. I.e. { "6002_2": "2025-02-15T00:00:00Z"}

        Returns:
            int: the new node id of the uploaded document

        """
        if self.__logger:
            self.__logger.debug(f'businessworkspace_hr_upload_file() start: {locals()}')

        retval = -1

        base_url = self.__check_url(base_url_cs)
        apiendpoint = f'api/v2/businessworkspace/preview'
        url = urllib.parse.urljoin(base_url, apiendpoint)

        params = { 'bw_id': bws_id }

        files = {'file': (remote_filename, open(os.path.join(local_folder, local_filename), 'rb'), 'application/octet-stream')}

        res = self.call_post_form_data(url, params, files)

        jres = json.loads(res)
        if self.__logger:
            self.__logger.debug(f'businessworkspace_hr_upload_file() preview finished: {jres}')

        if jres and jres.get('results', {}):
            retval = jres['results'].get('docNodeId', -1)

        if retval > 0:
            apiendpoint = f'api/v2/businessworkspace/{bws_id}/postupload'
            url = urllib.parse.urljoin(base_url, apiendpoint)

            params = {'docNodeId': retval, 'classification_id': classification_id, 'document_name': remote_filename }

            res = self.call_put(url, params)

            jres = json.loads(res)

            if jres and jres.get('results', {}):
                if jres['results'].get('ok', False) and jres['results'].get('errMsg', '') == '':
                    if self.__logger:
                        self.__logger.debug(f'businessworkspace_hr_upload_file() postupload - successfully applied classification')
                else:
                    error_message = f"Error in businessworkspace_hr_upload_file() postupload -> the classification was not applied successfully: {jres['results'].get('errMsg', '')}"
                    if self.__logger:
                        self.__logger.error(error_message)

                    if retval > 0:
                        try:
                            # clean up 999 Inbox folder
                            self.node_delete(base_url_cs, retval)
                            retval = -1
                        except Exception as innerErr:
                            error_message2 = f'Error in businessworkspace_hr_upload_file() postupload - cleanup failed: the file could not deleted from 999 Inbox: {innerErr}.'
                            if self.__logger:
                                self.__logger.error(error_message2)

                    raise Exception(error_message)

            if self.__logger:
                self.__logger.debug(f'businessworkspace_hr_upload_file() postupload finished: {jres}')

            if category:
                res = self.node_category_update(base_url_cs, retval, category_id, category)
                if self.__logger:
                    self.__logger.debug(f'businessworkspace_hr_upload_file() -> node_category_add() finished: {res}')

            if self.__logger:
                self.__logger.debug(f'businessworkspace_hr_upload_file() finished: {retval}')

        else:
            error_message = f'Error in businessworkspace_hr_upload_file() -> the file upload did not return a valid node Id: {res}'
            if self.__logger:
                self.__logger.error(error_message)
            raise Exception(error_message)

        return retval

    def businessworkspace_hr_upload_bytes(self, base_url_cs: str, bws_id: int, content_bytes: bytes, remote_filename: str, classification_id: int, category_id: int, category: dict) -> int:
        """ Upload Document into HR workspace as Byte Array.

        Args:
            base_url_cs (str):
                The URL to be called. I.e. http://content-server/otcs/cs.exe

            bws_id (str):
                The NodeID of the Business Workspace.

            content_bytes (bytes):
                The bytearray containing the file's content.

            remote_filename (str):
                The remote file name of the document.

            classification_id (int):
                The Node ID of the document type (ID of classification) of the document.

            category_id (int):
                The Node ID of the category (containing the Date Of Origin) of the document.

            category (dict):
                The category containing usually the date of origin of the document. I.e. { "6002_2": "2025-02-15T00:00:00Z"}

        Returns:
            int: the new node id of the uploaded document

        """
        if self.__logger:
            self.__logger.debug(f'businessworkspace_hr_upload_bytes() start: {locals()}')

        retval = -1

        base_url = self.__check_url(base_url_cs)
        apiendpoint = f'api/v2/businessworkspace/preview'
        url = urllib.parse.urljoin(base_url, apiendpoint)

        params = { 'bw_id': bws_id }

        files = {'file': (remote_filename, content_bytes, 'application/octet-stream')}

        res = self.call_post_form_data(url, params, files)

        jres = json.loads(res)
        if self.__logger:
            self.__logger.debug(f'businessworkspace_hr_upload_bytes() preview finished: {jres}')

        if jres and jres.get('results', {}):
            retval = jres['results'].get('docNodeId', -1)

        if retval > 0:
            apiendpoint = f'api/v2/businessworkspace/{bws_id}/postupload'
            url = urllib.parse.urljoin(base_url, apiendpoint)

            params = {'docNodeId': retval, 'classification_id': classification_id, 'document_name': remote_filename }

            res = self.call_put(url, params)

            jres = json.loads(res)

            if jres and jres.get('results', {}):
                if jres['results'].get('ok', False) and jres['results'].get('errMsg', '') == '':
                    if self.__logger:
                        self.__logger.debug(f'businessworkspace_hr_upload_bytes() postupload - successfully applied classification')
                else:
                    error_message = f"Error in businessworkspace_hr_upload_bytes() postupload -> the classification was not applied successfully: {jres['results'].get('errMsg', '')}"
                    if self.__logger:
                        self.__logger.error(error_message)

                    if retval > 0:
                        try:
                            # clean up 999 Inbox folder
                            self.node_delete(base_url_cs, retval)
                            retval = -1
                        except Exception as innerErr:
                            error_message2 = f'Error in businessworkspace_hr_upload_file() postupload - cleanup failed: the file could not deleted from 999 Inbox: {innerErr}.'
                            if self.__logger:
                                self.__logger.error(error_message2)

                    raise Exception(error_message)

            if self.__logger:
                self.__logger.debug(f'businessworkspace_hr_upload_bytes() postupload finished: {jres}')

            if category:
                res = self.node_category_update(base_url_cs, retval, category_id, category)
                if self.__logger:
                    self.__logger.debug(f'businessworkspace_hr_upload_bytes() -> node_category_add() finished: {res}')

            if self.__logger:
                self.__logger.debug(f'businessworkspace_hr_upload_bytes() finished: {retval}')

        else:
            error_message = f'Error in businessworkspace_hr_upload_bytes() -> the file upload did not return a valid node Id: {res}'
            if self.__logger:
                self.__logger.error(error_message)
            raise Exception(error_message)

        return retval

    def node_permissions_owner_apply(self, base_url_cs: str, node_id: int, new_perms: dict) -> int:
        """ Apply the Owner Permissions to a Node

        Args:
            base_url_cs (str):
                The URL to be called. I.e. http://content-server/otcs/cs.exe

            node_id (int):
                The Node ID to update.

            new_perms (dict):
                The new Permissions. I.e. { "permissions":["see","see_contents"] } or { "permissions":["see","see_contents"], "right_id": 1000, "apply_to":0 }
                The allowable values for permissions are:
                "see"
                "see_contents"
                "modify"
                "edit_attributes"
                "add_items"
                "reserve"
                "add_major_version"
                "delete_versions"
                "delete"
                "edit_permissions"

                Apply the change to different levels:
                0 This Item
                1 Sub-Items
                2 This Item and Sub-Items
                3 This Item And Immediate Sub-Items

        Returns:
            int: the Node ID which is updated.

        """
        if self.__logger:
            self.__logger.debug(f'node_permissions_owner_apply() start: {locals()}')
        retval = -1
        base_url = self.__check_url(base_url_cs)
        apiendpoint = f'api/v2/nodes/{node_id}/permissions/owner'
        url = urllib.parse.urljoin(base_url, apiendpoint)

        params = {'body': json.dumps(new_perms)}

        res = self.call_put(url, params)

        jres = json.loads(res)

        if jres:
            retval = node_id

        if self.__logger:
            self.__logger.debug(f'node_permissions_owner_apply() finished: {retval}')

        return retval

    def node_permissions_owner_delete(self, base_url_cs: str, node_id: int) -> int:
        """ Delete the Owner Permissions from a Node

        Args:
            base_url_cs (str):
                The URL to be called. I.e. http://content-server/otcs/cs.exe

            node_id (int):
                The Node ID to update.

        Returns:
            int: the Node ID which is updated.

        """
        if self.__logger:
            self.__logger.debug(f'node_permissions_owner_delete() start: {locals()}')
        retval = -1
        base_url = self.__check_url(base_url_cs)
        apiendpoint = f'api/v2/nodes/{node_id}/permissions/owner'
        url = urllib.parse.urljoin(base_url, apiendpoint)

        res = self.call_delete(url)

        jres = json.loads(res)

        if jres:
            retval = node_id

        if self.__logger:
            self.__logger.debug(f'node_permissions_owner_delete() finished: {retval}')

        return retval

    def node_permissions_group_apply(self, base_url_cs: str, node_id: int, new_perms: dict) -> int:
        """ Apply the Group Permissions to a Node

        Args:
            base_url_cs (str):
                The URL to be called. I.e. http://content-server/otcs/cs.exe

            node_id (int):
                The Node ID to update.

            new_perms (dict):
                The new Permissions. I.e. { "permissions":["see","see_contents"] } or { "permissions":["see","see_contents"], "right_id": 2001, "apply_to":0 }
                The allowable values for permissions are:
                "see"
                "see_contents"
                "modify"
                "edit_attributes"
                "add_items"
                "reserve"
                "add_major_version"
                "delete_versions"
                "delete"
                "edit_permissions"

                Apply the change to different levels:
                0 This Item
                1 Sub-Items
                2 This Item and Sub-Items
                3 This Item And Immediate Sub-Items

        Returns:
            int: the Node ID which is updated.

        """
        if self.__logger:
            self.__logger.debug(f'node_permissions_group_apply() start: {locals()}')
        retval = -1
        base_url = self.__check_url(base_url_cs)
        apiendpoint = f'api/v2/nodes/{node_id}/permissions/group'
        url = urllib.parse.urljoin(base_url, apiendpoint)

        params = {'body': json.dumps(new_perms)}

        res = self.call_put(url, params)

        jres = json.loads(res)

        if jres:
            retval = node_id

        if self.__logger:
            self.__logger.debug(f'node_permissions_group_apply() finished: {retval}')

        return retval

    def node_permissions_group_delete(self, base_url_cs: str, node_id: int) -> int:
        """ Delete the Group Permissions from a Node

        Args:
            base_url_cs (str):
                The URL to be called. I.e. http://content-server/otcs/cs.exe

            node_id (int):
                The Node ID to update.

        Returns:
            int: the Node ID which is updated.

        """
        if self.__logger:
            self.__logger.debug(f'node_permissions_group_delete() start: {locals()}')
        retval = -1
        base_url = self.__check_url(base_url_cs)
        apiendpoint = f'api/v2/nodes/{node_id}/permissions/group'
        url = urllib.parse.urljoin(base_url, apiendpoint)

        res = self.call_delete(url)

        jres = json.loads(res)

        if jres:
            retval = node_id

        if self.__logger:
            self.__logger.debug(f'node_permissions_group_delete() finished: {retval}')

        return retval

    def node_permissions_public_apply(self, base_url_cs: str, node_id: int, new_perms: dict) -> int:
        """ Apply the Public Permissions to a Node

        Args:
            base_url_cs (str):
                The URL to be called. I.e. http://content-server/otcs/cs.exe

            node_id (int):
                The Node ID to update.

            new_perms (dict):
                The new Permissions. I.e. { "permissions":["see","see_contents"] } or { "permissions":["see","see_contents"], "apply_to":0 }
                There is no "right_id" as it is public.
                The allowable values for permissions are:
                "see"
                "see_contents"
                "modify"
                "edit_attributes"
                "add_items"
                "reserve"
                "add_major_version"
                "delete_versions"
                "delete"
                "edit_permissions"

                Apply the change to different levels:
                0 This Item
                1 Sub-Items
                2 This Item and Sub-Items
                3 This Item And Immediate Sub-Items

        Returns:
            int: the Node ID which is updated.

        """
        if self.__logger:
            self.__logger.debug(f'node_permissions_public_apply() start: {locals()}')
        retval = -1
        base_url = self.__check_url(base_url_cs)
        apiendpoint = f'api/v2/nodes/{node_id}/permissions/public'
        url = urllib.parse.urljoin(base_url, apiendpoint)

        params = {'body': json.dumps(new_perms)}

        res = self.call_put(url, params)

        jres = json.loads(res)

        if jres:
            retval = node_id

        if self.__logger:
            self.__logger.debug(f'node_permissions_public_apply() finished: {retval}')

        return retval

    def node_permissions_public_delete(self, base_url_cs: str, node_id: int) -> int:
        """ Delete the Public Permissions from a Node

        Args:
            base_url_cs (str):
                The URL to be called. I.e. http://content-server/otcs/cs.exe

            node_id (int):
                The Node ID to update.

        Returns:
            int: the Node ID which is updated.

        """
        if self.__logger:
            self.__logger.debug(f'node_permissions_public_delete() start: {locals()}')
        retval = -1
        base_url = self.__check_url(base_url_cs)
        apiendpoint = f'api/v2/nodes/{node_id}/permissions/public'
        url = urllib.parse.urljoin(base_url, apiendpoint)

        res = self.call_delete(url)

        jres = json.loads(res)

        if jres:
            retval = node_id

        if self.__logger:
            self.__logger.debug(f'node_permissions_public_delete() finished: {retval}')

        return retval

    def node_permissions_custom_apply(self, base_url_cs: str, node_id: int, new_perms: list) -> int:
        """ Add new Custom Permissions to a Node

        Args:
            base_url_cs (str):
                The URL to be called. I.e. http://content-server/otcs/cs.exe

            node_id (int):
                The Node ID to update.

            new_perms (list):
                The new Permissions. I.e. [{"permissions":["see", "see_contents", "modify"], "right_id": 1001}] or [{"permissions":["see", "see_contents", "modify"], "right_id": 1001, "apply_to": 0}]
                The allowable values for permissions are:
                "see"
                "see_contents"
                "modify"
                "edit_attributes"
                "add_items"
                "reserve"
                "add_major_version"
                "delete_versions"
                "delete"
                "edit_permissions"

                Apply the change to different levels:
                0 This Item
                1 Sub-Items
                2 This Item and Sub-Items
                3 This Item And Immediate Sub-Items

        Returns:
            int: the Node ID which is updated.

        """
        if self.__logger:
            self.__logger.debug(f'node_permissions_custom_add() start: {locals()}')
        retval = -1
        base_url = self.__check_url(base_url_cs)
        apiendpoint = f'api/v2/nodes/{node_id}/permissions/custom/bulk'
        url = urllib.parse.urljoin(base_url, apiendpoint)

        params = {'permissions_array': json.dumps(new_perms)}

        res = self.call_post_form_url_encoded(url, params)

        jres = json.loads(res)

        if jres:
            retval = node_id

        if self.__logger:
            self.__logger.debug(f'node_permissions_custom_add() finished: {retval}')

        return retval

    def node_permissions_custom_update(self, base_url_cs: str, node_id: int, right_id: int, new_perms: dict) -> int:
        """ Update the Custom Permissions of a specific Right ID to a Node

        Args:
            base_url_cs (str):
                The URL to be called. I.e. http://content-server/otcs/cs.exe

            node_id (int):
                The Node ID to update.

            right_id (int):
                The Content Server User or Group ID to update.

            new_perms (dict):
                The new Permissions. I.e. { "permissions":["see","see_contents"] } or { "permissions":["see","see_contents"], "apply_to":0 }
                There is no "right_id" in the dict structure here as it is passed as a URL parameter.
                The allowable values for permissions are:
                "see"
                "see_contents"
                "modify"
                "edit_attributes"
                "add_items"
                "reserve"
                "add_major_version"
                "delete_versions"
                "delete"
                "edit_permissions"

                Apply the change to different levels:
                0 This Item
                1 Sub-Items
                2 This Item and Sub-Items
                3 This Item And Immediate Sub-Items

        Returns:
            int: the Node ID which is updated.

        """
        if self.__logger:
            self.__logger.debug(f'node_permissions_custom_update() start: {locals()}')
        retval = -1
        base_url = self.__check_url(base_url_cs)
        apiendpoint = f'api/v2/nodes/{node_id}/permissions/custom/{right_id}'
        url = urllib.parse.urljoin(base_url, apiendpoint)

        params = {'body': json.dumps(new_perms)}

        res = self.call_put(url, params)

        jres = json.loads(res)

        if jres:
            retval = node_id

        if self.__logger:
            self.__logger.debug(f'node_permissions_custom_update() finished: {retval}')

        return retval

    def node_permissions_custom_delete(self, base_url_cs: str, node_id: int, right_id: int) -> int:
        """ Delete the Custom Permissions of a specific Right ID from a Node

        Args:
            base_url_cs (str):
                The URL to be called. I.e. http://content-server/otcs/cs.exe

            node_id (int):
                The Node ID to update.

            right_id (int):
                The Content Server User or Group ID to update.

        Returns:
            int: the Node ID which is updated.

        """
        if self.__logger:
            self.__logger.debug(f'node_permissions_custom_delete() start: {locals()}')
        retval = -1
        base_url = self.__check_url(base_url_cs)
        apiendpoint = f'api/v2/nodes/{node_id}/permissions/custom/{right_id}'
        url = urllib.parse.urljoin(base_url, apiendpoint)

        res = self.call_delete(url)

        jres = json.loads(res)

        if jres:
            retval = node_id

        if self.__logger:
            self.__logger.debug(f'node_permissions_custom_delete() finished: {retval}')

        return retval

    def webreport_nickname_call(self, base_url_cs: str, nickname: str, params: dict) -> str:
        """ Call WebReport by Nickname and pass Parameters by POST method (form-data)

        Args:
            base_url_cs (str):
                The URL to be called. I.e. http://content-server/otcs/cs.exe

            nickname (str):
                The Nickname of the WebReport.

            params (dict):
                The Parameters to be passed to the WebReport. I.e. { "p_name": "name", "p_desc": "description" }

        Returns:
            str: the Result of the WebReport

        """
        if self.__logger:
            self.__logger.debug(f'webreport_nickname_call() start: {locals()}')
        retval = ''
        base_url = self.__check_url(base_url_cs)
        apiendpoint = f'api/v1/webreports/{nickname}'
        url = urllib.parse.urljoin(base_url, apiendpoint)

        if not 'format' in params:
            params['format'] = 'webreport'

        retval = self.call_post_form_data(url, params, {})

        if self.__logger:
            self.__logger.debug(f'webreport_nickname_call() finished: {retval}')

        return retval

    def webreport_nodeid_call(self, base_url_cs: str, node_id: int, params: dict) -> str:
        """ Call WebReport by Nickname and pass Parameters by POST method (form-data)

        Args:
            base_url_cs (str):
                The URL to be called. I.e. http://content-server/otcs/cs.exe

            node_id (int):
                The NodeID of the WebReport.

            params (dict):
                The Parameters to be passed to the WebReport. I.e. { "p_name": "name", "p_desc": "description" }

        Returns:
            str: the Result of the WebReport

        """
        if self.__logger:
            self.__logger.debug(f'webreport_nodeid_call() start: {locals()}')
        retval = ''
        base_url = self.__check_url(base_url_cs)
        apiendpoint = f'api/v1/nodes/{node_id}/output'
        url = urllib.parse.urljoin(base_url, apiendpoint)

        if not 'format' in params:
            params['format'] = 'webreport'

        retval = self.call_post_form_data(url, params, {})

        if self.__logger:
            self.__logger.debug(f'webreport_nodeid_call() finished: {retval}')

        return retval

    def workflows_document_get_available(self, base_url_cs: str, parent_id: int, document_id: int) -> list:
        """ Get available Document Workflows

        Args:
            base_url_cs (str):
                The URL to be called. I.e. http://content-server/otcs/cs.exe

            parent_id (int):
                The Node ID of the Parent in which the Document is stored.

            document_id (int):
                The Node ID of the Document for which the workflow is looked up for.

        Returns:
            list: available workflows

        """
        if self.__logger:
            self.__logger.debug(f'workflows_document_get_available() start: {locals()}')
        retval = []
        base_url = self.__check_url(base_url_cs)
        apiendpoint = f'api/v2/docworkflows'
        url = urllib.parse.urljoin(base_url, apiendpoint)

        params = { 'doc_id': document_id, 'parent_id': parent_id }

        res = self.call_get(url, params)

        jres = json.loads(res)

        if jres and jres.get('results', {}) and jres['results'].get('data', []):
            retval = jres['results'].get('data', [])

        if self.__logger:
            self.__logger.debug(f'workflows_document_get_available() finished: {retval}')

        return retval

    def workflows_document_draft_create(self, base_url_cs: str, workflow_id: int, document_ids: str) -> dict:
        """ Create a new Draft Process for the Document Workflow

        Args:
            base_url_cs (str):
                The URL to be called. I.e. http://content-server/otcs/cs.exe

            workflow_id (int):
                The ID of the workflow to be created.

            document_ids (str):
                The Node IDs of the Documents for which the workflow is created. I.e. "130480" or "130480,132743"

        Returns:
            dict: Result of the draftprocess creation. I.e. { "draftprocess_id": 134043, "workflow_type": "1_1" }

        """
        if self.__logger:
            self.__logger.debug(f'workflows_document_draft_create() start: {locals()}')
        retval = {}
        base_url = self.__check_url(base_url_cs)
        apiendpoint = f'api/v2/draftprocesses'
        url = urllib.parse.urljoin(base_url, apiendpoint)

        data = { 'workflow_id': workflow_id, 'doc_ids': document_ids }
        params = { 'body': json.dumps(data) }

        res = self.call_post_form_data(url, params, {})

        jres = json.loads(res)

        if jres and jres.get('results', {}):
            retval = jres.get('results', {})

        if self.__logger:
            self.__logger.debug(f'workflows_document_draft_create() finished: {retval}')

        return retval

    def workflows_document_draft_form_get(self, base_url_cs: str, draft_id: int) -> dict:
        """ Get form for the Draft Process

        Args:
            base_url_cs (str):
                The URL to be called. I.e. http://content-server/otcs/cs.exe

            draft_id (int):
                The ID of the Draft Process.

        Returns:
            dict: Result of the form information of the draftprocess. I.e. { 'data': {...}, 'forms': [...] }

        """
        if self.__logger:
            self.__logger.debug(f'workflows_document_draft_form_get() start: {locals()}')
        retval = {}
        base_url = self.__check_url(base_url_cs)
        apiendpoint = f'api/v1/forms/draftprocesses/update'
        url = urllib.parse.urljoin(base_url, apiendpoint)

        params = { 'draftprocess_id': draft_id }

        res = self.call_get(url, params)

        retval = json.loads(res)

        if self.__logger:
            self.__logger.debug(f'workflows_document_draft_form_get() finished: {retval}')

        return retval

    def workflows_document_draft_initiate(self, base_url_cs: str, draft_id: int, comment: str) -> dict:
        """ Initiate the Draft Process

        Args:
            base_url_cs (str):
                The URL to be called. I.e. http://content-server/otcs/cs.exe

            draft_id (int):
                The ID of the Draft Process.

            comment (str):
                The comment to be applied to the Initiation Draft Process.

        Returns:
            dict: Result of the draftprocess initiation. I.e. {'custom_message': None, 'process_id': 134687, 'WorkID': None, 'WRID': None}

        """
        if self.__logger:
            self.__logger.debug(f'workflows_document_draft_initiate() start: {locals()}')
        retval = {}
        base_url = self.__check_url(base_url_cs)
        apiendpoint = f'api/v2/draftprocesses/{draft_id}'
        url = urllib.parse.urljoin(base_url, apiendpoint)

        data = { 'action': 'Initiate', 'comment': comment }
        params = { 'body': json.dumps(data) }

        res = self.call_put(url, params)

        jres = json.loads(res)

        if jres and jres.get('results', {}):
            retval = jres.get('results', {})

        if self.__logger:
            self.__logger.debug(f'workflows_document_draft_initiate() finished: {retval}')

        return retval
