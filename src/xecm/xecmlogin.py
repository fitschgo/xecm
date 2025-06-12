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

class XECMLogin:
    """ Do Login and get OTCSTicket, OTDSTicket or Bearer Token """
    _logger: logging.Logger
    _useragent = 'Chrome XECM'
    _base_url = ''
    _ticket = ''
    _usr = ''
    _pwd = ''

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
                self._logger = logger
            else:
                self._logger = None

            # url check if last char is / and add it if missing
            self._base_url = login_url
            self._usr = user_or_client_id
            self._pwd = pw_or_client_secret

            if self._base_url and self._base_url != '' and len(self._base_url) > 1:
                if self._base_url[-1] != '/':
                    self._base_url += '/'

            # check login_type OTCS_TICKET or OTDS_TICKET or OTDS_BEARER (default)
            if login_type == LoginType.OTCS_TICKET:
                if self._logger:
                    self._logger.info(f'Create OTCSTicket with username and password.')
                self._ticket = self._otcs_login(self._usr, self._pwd)
                if self._logger:
                    self._logger.info(f'OTCSTicket created.')
            elif login_type == LoginType.OTDS_TICKET:
                if self._logger:
                    self._logger.info(f'Create OTDSTicket with username and password.')
                self._ticket = self._otds_login(self._usr, self._pwd)
                if self._logger:
                    self._logger.info(f'OTDSTicket created.')
            else:
                if self._logger:
                    self._logger.info(f'Create Bearer Token in OTDS with client_id and client_secret.')
                self._ticket = self._otds_token(self._usr, self._pwd)
                if self._logger:
                    self._logger.info(f'Bearer Token created.')

        except Exception as innerErr:
            error_message = f'XECMLogin Error during init: {innerErr}.'
            if self._logger:
                self._logger.info(error_message)
            raise Exception(error_message)

        if self._logger:
            self._logger.info(f'XECMLogin successful: {self._ticket}')

    def _otcs_login(self, username: str, password: str) -> str:
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
        url = urllib.parse.urljoin(self._base_url, apiendpoint)

        params = { 'username': username, 'password': password }

        # do REST API call to CS
        r = requests.post(url=url, data=params,
                          headers={'User-Agent': self._useragent,
                                   'Content-Type': 'application/x-www-form-urlencoded'})

        if self._logger:
            self._pretty_print_POST(r.request)

        if r.ok:
            # get OTCSTicket from response
            r_text = r.text

            if self._logger:
                self._logger.debug(f'-----------RESPONSE-----------\r\n{r_text}')

            try:
                resObj = json.loads(r_text)
                otcsticket = resObj.get('ticket', '')
            except Exception as innerErr:
                error_message = f'Login Error OTCSTicket on {url} on Result Parse: {innerErr}. Response was {r_text}'
                if self._logger:
                    self._logger.error(error_message)
                raise Exception(error_message)

            if otcsticket == '':
                error_message = f'Login Error on {url}: no OTCS ticket created. Response was {r_text}'
                if self._logger:
                    self._logger.error(error_message)
                raise Exception(error_message)

        else:
            error_message = f'Login Error on {url}: {r.status_code} {r.text}'
            if self._logger:
                self._logger.error(error_message)
            raise Exception(error_message)

        return otcsticket

    def _otds_login(self, username: str, password: str) -> str:
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
        url = urllib.parse.urljoin(self._base_url, apiendpoint)

        params = { 'user_name': username, 'password': password }

        # do REST API call to CS
        r = requests.post(url=url, data=json.dumps(params),
                          headers={'User-Agent': self._useragent,
                                   'Content-Type': 'application/json;charset=utf-8'})

        if self._logger:
            self._pretty_print_POST(r.request)

        if r.ok:
            # get OTDSTicket from response
            r_text = r.text

            if self._logger:
                self._logger.debug(f'-----------RESPONSE-----------\r\n{r_text}')

            try:
                resObj = json.loads(r_text)
                otdsticket = resObj.get('ticket', '')
            except Exception as innerErr:
                error_message = f'Login Error OTDSTicket on {url} on Result Parse: {innerErr}. Response was {r_text}'
                if self._logger:
                    self._logger.error(error_message)
                raise Exception(error_message)

            if otdsticket == '':
                error_message = f'Login Error on {url}: no OTDS ticket created. Response was {r_text}'
                if self._logger:
                    self._logger.error(error_message)
                raise Exception(error_message)

        else:
            error_message = f'Login Error on {url}: {r.status_code} {r.text}'
            if self._logger:
                self._logger.error(error_message)
            raise Exception(error_message)

        return otdsticket

    def _otds_token(self, client_id: str, client_secret: str) -> str:
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
        url = urllib.parse.urljoin(self._base_url, apiendpoint)

        params = { 'grant_type': 'client_credentials', 'requested_token_type': 'urn:ietf:params:oauth:token-type:access_token' }

        # do REST API call to CS
        r = requests.post(url=url, data=params,
                          headers={'User-Agent': self._useragent,
                                   'Content-Type': 'application/x-www-form-urlencoded'}, auth=(client_id, client_secret))

        if self._logger:
            self._pretty_print_POST(r.request)

        if r.ok:
            # get OTDSTicket from response
            r_text = r.text

            if self._logger:
                self._logger.debug(f'-----------RESPONSE-----------\r\n{r_text}')

            try:
                resObj = json.loads(r_text)
                bearer_token = resObj.get('access_token', '')
            except Exception as innerErr:
                error_message = f'Login Error Bearer Token on {url} on Result Parse: {innerErr}. Response was {r_text}'
                if self._logger:
                    self._logger.error(error_message)
                raise Exception(error_message)

            if bearer_token == '':
                error_message = f'Login Error on {url}: no OTDS Bearer Token created. Response was {r_text}'
                if self._logger:
                    self._logger.error(error_message)
                raise Exception(error_message)

        else:
            error_message = f'Login Error on {url}: {r.status_code} {r.text}'
            if self._logger:
                self._logger.error(error_message)
            raise Exception(error_message)

        return bearer_token

    def _pretty_print_POST(self, req: requests.PreparedRequest) -> None:
        """Pretty Print request to log

        Args:
            req (PreparedRequest):
                The request instance.

        Returns:
            None

        """
        if self._logger:
            self._logger.debug('{}\n{}\r\n{}\r\n\r\n{}'.format(
                '-----------REQUEST-----------',
                req.method + ' ' + req.url,
                '\r\n'.join('{}: {}'.format(k, v) for k, v in req.headers.items()),
                req.body,
            ))
