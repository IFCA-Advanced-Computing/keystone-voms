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
import uuid

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
SSL_CLIENT_CERT_CHAIN_ENV_PREFIX = "SSL_CLIENT_CERT_CHAIN_"


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

        self.domain = CONF.identity.default_domain_id or "default"

        super(VomsAuthNMiddleware, self).__init__(*args, **kwargs)

    @staticmethod
    def _get_cert_chain(ssl_info):
        """Return certificate and chain from the ssl info in M2Crypto format"""

        cert = M2Crypto.X509.load_cert_string(ssl_info.get("cert", ""))
        chain = M2Crypto.X509.X509_Stack()
        for c in ssl_info.get("chain", []):
            aux = M2Crypto.X509.load_cert_string(c)
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

    def _get_project_mapping(self, vo, fqan):
        voinfo = self.voms_json.get(fqan, {})

        # If no FQAN matched, try with the VO name
        if not voinfo:
            voinfo = self.voms_json.get(vo, {})

        tenant_name = voinfo.get("tenant", None)
        if tenant_name is None:
            raise exception.Unauthorized("Your VO is not authorized")
        return tenant_name

    def is_applicable(self, request):
        """Check if the request is applicable for this handler or not"""
        params = request.environ.get(PARAMS_ENV, {})
        auth = params.get("auth", {})
        if "voms" in auth:
            if auth["voms"] is True:
                return True
            else:
                raise exception.ValidationError("Error in JSON, 'voms' "
                                                "must be set to true")
        return False

    def _get_project(self, tenant_from_req, voms_info):
        user_dn = voms_info["user"]
        user_vo = voms_info["voname"]
        user_fqans = voms_info["fqans"]
        user_vo_groups = []
        for fqan in user_fqans:
            vo_group, vo_role, vo_capability = self._split_fqan(fqan)
            user_vo_groups.append(vo_group)

        if tenant_from_req not in [user_vo] + user_vo_groups:
            raise exception.ValidationError(
                "Requested 'tenantName' is not applicable: "
                "%s" % tenant_from_req)
        tenant_from_voms = self._get_project_mapping(user_vo, tenant_from_req)
        try:
            tenant_ref = self.identity_api.get_project_by_name(
                self.identity_api, tenant_from_voms, self.domain)
        except exception.ProjectNotFound:
            raise

        # NOTE(aloga): This is a bit tricky. If the user has been autocreated
        # it might not be associated with the tenant (i.e. it was created
        # during an unscoped request, therefore if the user is allowed and we
        # have autocreate users, we have to check and add it to the tenant
        if CONF.voms.autocreate_users:
            user_ref = self.identity_api.get_user_by_name(
                self.identity_api, user_dn, self.domain)
            tenants = self.identity_api.get_projects_for_user(
                self.identity_api, user_ref["id"])
            if tenant_ref["id"] not in tenants:
                LOG.info(_("Automatically adding user %s to tenant %s") %
                        (user_dn, tenant_ref["name"]))
                self.identity_api.add_user_to_project(
                    self.identity_api,
                    tenant_ref["id"],
                    user_ref["id"])

        return tenant_ref["name"]

    def _get_user(self, voms_info):
        user_dn = voms_info["user"]
        try:
            user_ref = self.identity_api.get_user_by_name(
                self.identity_api, user_dn, self.domain)
        except exception.UserNotFound:
            if CONF.voms.autocreate_users:
                user_id = uuid.uuid4().hex
                LOG.info(_("Autocreating REMOTE_USER %s with id %s") %
                        (user_id, user_dn))
                # TODO(aloga): add backend information un user referece?
                user = {
                    "id": user_id,
                    "name": user_dn,
                    "enabled": True,
                    "domain_id": self.domain,
                }
                self.identity_api.create_user(self.identity_api,
                                              user_id,
                                              user)
            else:
                LOG.debug(_("REMOTE_USER %s not found") % user_dn)
                raise
        return user_dn

    def process_request(self, request):
        if request.environ.get('REMOTE_USER', None) is not None:
            # authenticated upstream
            return self.application

        if not self.is_applicable(request):
            return self.application

        ssl_dict = {
            "dn": request.environ.get(SSL_CLIENT_S_DN_ENV, None),
            "cert": request.environ.get(SSL_CLIENT_CERT_ENV, None),
            "chain": [],
        }

        for k, v in request.environ.iteritems():
            if k.startswith(SSL_CLIENT_CERT_CHAIN_ENV_PREFIX):
                ssl_dict["chain"].append(v)

        params = request.environ.get(PARAMS_ENV)
        tenant_from_req = params["auth"].get("tenantName", None)

        try:
            voms_info = self._get_voms_info(ssl_dict)
        except VomsError as e:
            return wsgi.render_exception(e)

        try:
            user_dn = self._get_user(voms_info)
        except exception.UserNotFound as e:
            return wsgi.render_exception(e)

        # Scoped request. We must translate from VOMS fqan to local tenant and
        # mangle the dictionary
        if tenant_from_req is not None:
            try:
                tenant_from_voms = self._get_project(tenant_from_req, voms_info)
                params["auth"]["tenantName"] = tenant_from_voms
                request.environ[PARAMS_ENV] = params
            except exception.ProjectNotFound:
                e = exception.Unauthorized(message="VO is not accepted")
                return wsgi.render_exception(e)

        request.environ['REMOTE_USER'] = user_dn
