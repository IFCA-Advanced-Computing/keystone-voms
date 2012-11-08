# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 Spanish National Research Council
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import collections
import commands
import ctypes
import os
import tempfile

import M2Crypto

from keystone.common import logging
from keystone.common import wsgi
from keystone import exception
from keystone import identity
import keystone.middleware
from keystone.openstack.common import cfg
from keystone.openstack.common import jsonutils

from keystone_voms import voms_helper

LOG = logging.getLogger(__name__)

CONF = cfg.CONF
opts = [
    cfg.StrOpt("voms_policy", default="/etc/keystone/voms.json"),
    cfg.StrOpt("vomsdir_path", default="/etc/grid-security/vomsdir/"),
    cfg.StrOpt("ca_path", default="/etc/grid-security/certificates/"),
    cfg.StrOpt("vomsapi_lib", default="libvomsapi.so.1"),
    cfg.BoolOpt("autocreate_users", default=False),
]
CONF.register_opts(opts, group="voms")

PARAMS_ENV = keystone.middleware.PARAMS_ENV
CONTEXT_ENV = keystone.middleware.CONTEXT_ENV

SSL_CLIENT_S_DN_ENV = "SSL_CLIENT_S_DN"
SSL_CLIENT_CERT_ENV = "SSL_CLIENT_CERT"
SSL_CLIENT_CERT_CHAIN_0_ENV = "SSL_CLIENT_CERT_CHAIN_0"


class VomsError(exception.Error):
    """Voms credential management error"""

    errors = {
        0: ('none', None),
        1: ('nosocket', 'Socket problem'),
        2: ('noident', 'Cannot identify itself (certificate problem)'),
        3: ('comm', 'Server problem'),
        4: ('param', 'Wrong parameters'),
        5: ('noext', 'VOMS extension missing'),
        6: ('noinit', 'Initialization error'),
        7: ('time', 'Error in time checking'),
        8: ('idcheck', 'User data in extension different from the real'),
        9: ('extrainfo', 'VO name and URI missing'),
        10: ('format', 'Wrong data format'),
        11: ('nodata', 'Empty extension'),
        12: ('parse', 'Parse error'),
        13: ('dir', 'Directory error'),
        14: ('sign', 'Signature error'),
        15: ('server', 'Unidentifiable VOMS server'),
        16: ('mem', 'Memory problems'),
        17: ('verify', 'Generic verification error'),
        18: ('type', 'Returned data of unknown type'),
        19: ('order', 'Ordering different than required'),
        20: ('servercode', 'Error from the server'),
        21: ('notavail', 'Method not available'),
    }

    http_codes = {
        5: (400, "Bad Request"),
        11: (400, "Bad Request"),
        14: (401, "Not Authorized"),
    }

    def __init__(self, code):
        short, message = self.errors.get(code, ('oops',
                                                'Unknown error %d' % code))
        message = "(%s, %s)" % (code, message)
        super(VomsError, self).__init__(message=message)

        code, title = self.http_codes.get(code, (500, "Unexpected Error"))
        self.code = code
        self.title = title


class VomsAuthNMiddleware(wsgi.Middleware):
    """Filter that checks for the SSL data in the reqest.

    Sets 'ssl' in the context as a dictionary containing this data.
    """
    def __init__(self, *args, **kwargs):
        self.identity_api = identity.Manager()

        # VOMS stuff
        try:
            self.voms_json = jsonutils.loads(
                open(CONF.voms.voms_policy).read())
        except ValueError:
            raise exception.UnexpectedError("Bad formatted VOMS json data "
                                            "from %s" % CONF.voms.voms_policy)
        except:
            raise exception.UnexpectedError("Could not load VOMS json file "
                                            "%s" % CONF.voms.voms_policy)

        self.VOMSDIR = CONF.voms.vomsdir_path
        self.CADIR = CONF.voms.ca_path
        self._no_verify = False

        super(VomsAuthNMiddleware, self).__init__(*args, **kwargs)

    @staticmethod
    def _get_cert_chain(ssl_info):
        """Return certificate and chain from the ssl info in M2Crypto format"""

        cert = ssl_info.get(SSL_CLIENT_CERT_ENV, "")
        chain = ssl_info.get(SSL_CLIENT_CERT_CHAIN_0_ENV, "")
        cert = M2Crypto.X509.load_cert_string(cert)
        aux = M2Crypto.X509.load_cert_string(chain)
        chain = M2Crypto.X509.X509_Stack()
        chain.push(aux)
        return cert, chain

    def _get_voms_info(self, ssl_info):
        """Extract voms info from ssl_info and return dict with it."""

        try:
            cert, chain = self._get_cert_chain(ssl_info)
        except M2Crypto.X509.X509Error:
            raise exception.ValidationError(
                attribute="SSL data",
                target=CONTEXT_ENV)

        with voms_helper.VOMS(CONF.voms.vomsdir_path,
                              CONF.voms.ca_path, CONF.voms.vomsapi_lib) as v:
            if self._no_verify:
                v.set_no_verify()
            voms_data = v.retrieve(cert, chain)
            if not voms_data:
                # TODO(aloga): move this to a keystone exception
                raise VomsError(v.error.value)

            d = {}
            for attr in ('user', 'userca', 'server', 'serverca',
                         'voname',  'uri', 'version', 'serial',
                         ('not_before', 'date1'), ('not_after', 'date2')):
                if isinstance(attr, basestring):
                    d[attr] = getattr(voms_data, attr)
                else:
                    d[attr[0]] = getattr(voms_data, attr[1])

            d["fqans"] = []
            for fqan in iter(voms_data.fqan):
                if fqan is None:
                    break
                d["fqans"].append(fqan)

        return d

    @staticmethod
    def _split_fqan(fqan):
        """
        gets a fqan and returns a tuple containing
        (vo/groups, role, capability)
        """
        l = fqan.split("/")
        capability = l.pop().split("=")[-1]
        role = l.pop().split("=")[-1]
        vogroup = "/".join(l)
        return (vogroup, role, capability)

    def _get_tenant_for_vo(self, vo, fqans):
        # only check the firs fqan.
        fqan = fqans.pop(0)
        vo_group, vo_role, vo_capability = self._split_fqan(fqan)

        voinfo = self.voms_json.get(vo_group, {})
        if not voinfo:
            voinfo = self.voms_json.get(vo, {})

        # default to vo name
        tenant_name = voinfo.get("tenant", vo)

        return tenant_name

    def _get_user_tenant(self, ssl_data):
        try:
            voms_info = self._get_voms_info(ssl_data)
        except VomsError as e:
            raise e

        user_dn = voms_info["user"]
        user_vo = voms_info["voname"]
        user_fqans = voms_info["fqans"]

        tenant_name = self._get_tenant_for_vo(user_vo, user_fqans)
        try:
            tenant_ref = self.identity_api.get_tenant_by_name(
                self.identity_api,
                tenant_name)
        except exception.TenantNotFound:
            raise

        try:
            user_ref = self.identity_api.get_user(self.identity_api, user_dn)
        except exception.UserNotFound:
            if CONF.voms.autocreate_users:
                user = {
                    "id": user_dn,
                    "name": user_dn,
                    "enabled": True,
                    "tenantId": tenant_ref["id"]
                }
                # user_dn is supossed to be unique
                self.identity_api.create_user(
                    self.identity_api,
                    user_dn,
                    user)
                self.identity_api.add_user_to_tenant(
                    self.identity_api,
                    tenant_ref["id"],
                    user_dn)
            else:
                raise

        return user_dn, tenant_ref["name"]

    def is_applicable(self, request):
        """Check if the request is applicable for this handler or not"""
        params = request.environ.get(PARAMS_ENV, {})
        auth = params.get("auth", {})
        if "voms" in auth:
            return True
        return False

    def process_request(self, request):
        if request.environ.get('REMOTE_USER', None) is not None:
            # authenticated upstream
            return self.application

        if not self.is_applicable(request):
            return self.application

        ssl_dict = {}
        for i in (SSL_CLIENT_S_DN_ENV,
                  SSL_CLIENT_CERT_ENV,
                  SSL_CLIENT_CERT_CHAIN_0_ENV):
            ssl_dict[i] = request.environ.get(i, None)

        try:
            user_dn, tenant = self._get_user_tenant(ssl_dict)
        except exception.UserNotFound:
            raise exception.Unauthorized(message="User not found")
        except exception.TenantNotFound:
            raise exception.Unauthorized(message="Your VO is not accepted")
        else:
            params = request.environ.get(PARAMS_ENV)
            if params["auth"].get("tenantName", None):
                raise exception.ValidationError(
                    "Found 'tenantName' in 'auth' when using "
                    "VOMS authentication")
            params["auth"]["tenantName"] = tenant
            request.environ[PARAMS_ENV] = params

            # indicate remote authentication via REMOTE_USER
            request.environ['REMOTE_USER'] = user_dn
