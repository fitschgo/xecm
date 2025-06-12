"""xecm - Simple Python Library to call Opentext Extended ECM REST API."""

from .xecmlogin import XECMLogin
from .xecmlogin import LoginType

__all__ = ["XECMLogin", "LoginType"]