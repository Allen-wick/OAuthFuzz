#!/usr/bin/env python3
"""Protocol package — target-specific OAuth implementations."""

from protocol.base import OAuthProtocolBase
from protocol.spring_authz import SpringAuthzProtocolMixin
from protocol.cxf_oauth import CxfOAuthProtocolMixin
from protocol.logto import LogtoProtocolMixin
from protocol.wso2 import Wso2ProtocolMixin
from protocol.shiro import ShiroProtocolMixin

# Backward-compat alias (all methods consolidated into OAuthProtocolBase)
GenericOIDCMixin = OAuthProtocolBase

__all__ = [
    'OAuthProtocolBase',
    'GenericOIDCMixin',
    'SpringAuthzProtocolMixin',
    'CxfOAuthProtocolMixin',
    'LogtoProtocolMixin',
    'Wso2ProtocolMixin',
    'ShiroProtocolMixin',
]
