__author__ = "Philipp Egger"
__copyright__ = "Copyright (C) 2025, Philipp Egger"
__credits__ = ["Philipp Egger"]
__maintainer__ = "Philipp Egger"
__email__ = "philipp.egger@handel-it.com"

import logging
import requests

default_logger = logging.getLogger("xecm.xecmlogin")

class XECMLogin:
    """ Do Login and get OTCSTicket, OTDSTicket or Bearer Token """

    logger: logging.Logger = default_logger

    _config: dict
    _session = None

    def __init__(
        self,
        otds_url: str,
        client_id: str,
        client_secret: str,
        base_url: str,
        username: str,
        password: str,
        logger: logging.Logger = default_logger,
    ) -> None:
        """Initialize the AVTS object.

        Args:
            otds_url (str):
                The URL of the OTDS Server used by Aviator Search.
            client_id (str):
                The client ID for the Aviator Search oAuth client.
            client_secret (str):
                The client secret for the Aviator Search oAuth client.
            base_url (str):
                The Aviator Search base URL.
            username (str):
                User with administrative permissions in Aviator Search.
            password (str):
                Password of the user with administrative permissions in Aviator Search.
            logger (logging.Logger, optional):
                The logging object to use for all log messages. Defaults to default_logger.

        """

        if logger != default_logger:
            self.logger = logger.getChild("xecmlogin")
            for logfilter in logger.filters:
                self.logger.addFilter(logfilter)

        self._config = {}
        self._session = requests.Session()

    # end method definition

    def config(self) -> dict:
        """Return the configuration dictionary.

        Returns:
            dict: Configuration dictionary

        """

        return self._config

    # end method definition
