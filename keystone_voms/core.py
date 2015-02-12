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

import uuid

import M2Crypto
from oslo.config import cfg

from keystone.common import wsgi
from keystone import exception as ks_exc
from keystone import identity, assignment
import keystone.middleware
from keystone.openstack.common.gettextutils import _
from keystone.openstack.common import jsonutils
from keystone.openstack.common import log

from keystone_voms import exception
from keystone_voms import voms_helper

LOG = log.getLogger(__name__)

CONF = cfg.CONF
opts = [
    cfg.StrOpt("voms_policy",
               default="/etc/keystone/voms.json",
               help="JSON file containing the VOMS mapping"),
    cfg.StrOpt("vomsdir_path",
               default="/etc/grid-security/vomsdir/",
               help="Path where VOMS LSC configurations are stored "
               "(vomsdir path)."),
    cfg.StrOpt("ca_path",
               default="/etc/grid-security/certificates/",
               help="Path where CA and CRLs are stored"),
    cfg.StrOpt("vomsapi_lib",
               default="libvomsapi.so.1",
               help="VOMS library to use"),
    cfg.BoolOpt("autocreate_users",
                default=False,
                help="If enabled, user not found on the local Identity "
                "backend will be created and added to the tenant "
                "automatically"),
    cfg.BoolOpt("add_roles",
                default=False,
                help="If enabled, users will get the roles defined in "
                "'user_roles' when created."),
    cfg.ListOpt("user_roles",
                default=["_member_"],
                help="List of roles to add to new users."),
]
CONF.register_opts(opts, group="voms")

PARAMS_ENV = keystone.middleware.PARAMS_ENV
CONTEXT_ENV = keystone.middleware.CONTEXT_ENV

SSL_CLIENT_S_DN_ENV = "SSL_CLIENT_S_DN"
SSL_CLIENT_CERT_ENV = "SSL_CLIENT_CERT"
SSL_CLIENT_CERT_CHAIN_ENV_PREFIX = "SSL_CLIENT_CERT_CHAIN_"


class VomsAuthNMiddleware(wsgi.Middleware):
    """Filter that checks for the SSL data in the reqest.

    Sets 'ssl' in the context as a dictionary containing this data.
    """
    def __init__(self, *args, **kwargs):
        self.identity_api = identity.Manager()
        self.assignment_api = assignment.Manager()

        # VOMS stuff
        try:
            self.voms_json = jsonutils.loads(
                open(CONF.voms.voms_policy).read())
        except ValueError:
            raise ks_exc.UnexpectedError("Bad formatted VOMS json data "
                                         "from %s" % CONF.voms.voms_policy)
        except:
            raise ks_exc.UnexpectedError("Could not load VOMS json file "
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
            if aux.check_ca():
                continue  # Don't include CA certs
            chain.push(aux)
        return cert, chain

    def _get_voms_info(self, ssl_info):
        """Extract voms info from ssl_info and return dict with it."""

        try:
            cert, chain = self._get_cert_chain(ssl_info)
        except M2Crypto.X509.X509Error:
            raise ks_exc.ValidationError(
                attribute="SSL data",
                target=CONTEXT_ENV)

        with voms_helper.VOMS(CONF.voms.vomsdir_path,
                              CONF.voms.ca_path, CONF.voms.vomsapi_lib) as v:
            if self._no_verify:
                v.set_no_verify()
            voms_data = v.retrieve(cert, chain)
            if not voms_data:
                # TODO(aloga): move this to a keystone exception
                raise exception.VomsError(v.error.value)

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

    def is_applicable(self, request):
        """Check if the request is applicable for this handler or not"""
        params = request.environ.get(PARAMS_ENV, {})
        auth = params.get("auth", {})
        if "voms" in auth:
            if auth["voms"] is True:
                return True
            else:
                raise ks_exc.ValidationError("Error in JSON, 'voms' "
                                             "must be set to true")
        return False

    def _get_project_from_voms(self, voms_info):
        user_vo = voms_info["voname"]
        user_fqans = voms_info["fqans"]
        for fqan in user_fqans:
            voinfo = self.voms_json.get(fqan, {})
            if voinfo is not {}:
                break
        # If no FQAN matched, try with the VO name
        if not voinfo:
            voinfo = self.voms_json.get(user_vo, {})

        tenant_name = voinfo.get("tenant", "")

        try:
            tenant_ref = self.assignment_api.get_project_by_name(tenant_name,
                                                                 self.domain)
        except ks_exc.ProjectNotFound:
            LOG.warning(_("VO mapping not properly configured for '%s'") %
                        user_vo)
            raise ks_exc.Unauthorized("Your VO is not authorized")

        return tenant_ref

    def _create_user(self, user_dn):
        LOG.info(_("Autocreating REMOTE_USER %s") % user_dn)
        # TODO(aloga): add backend information in user referece?
        user = {
            "name": user_dn,
            "enabled": True,
            "domain_id": self.domain,
        }
        return self.identity_api.create_user(user)

    def _add_user_to_tenant(self, user_id, tenant_id):
        LOG.info(_("Automatically adding user %s to tenant %s") %
                 (user_id, tenant_id))
        self.assignment_api.add_user_to_project(tenant_id, user_id)

    def _search_role(self, r_name):
        for role in self.assignment_api.list_roles():
            if role.get('name') == r_name:
                return role
        return None

    def _update_user_roles(self, user_id, tenant_id):
        # getting the role names is not straightforward
        # a get_role_by_name would be useful
        user_roles = self.assignment_api.get_roles_for_user_and_project(
            user_id, tenant_id)
        role_names = [self.assignment_api.get_role(role_id).get('name')
                      for role_id in user_roles]
        # add missing roles
        for r_name in CONF.voms.user_roles:
            if r_name in role_names:
                continue
            role = self._search_role(r_name)
            if not role:
                LOG.info(_("Role with name '%s' not found. Autocreating.")
                         % r_name)
                r_id = uuid.uuid4().hex
                role = {'id': r_id,
                        'name': r_name}
                self.assignment_api.create_role(r_id, role)
            LOG.debug(_("Adding role '%s' to user") % r_name)
            self.assignment_api.add_role_to_user_and_project(user_id,
                                                             tenant_id,
                                                             role['id'])

    def _get_user(self, voms_info, req_tenant):
        user_dn = voms_info["user"]
        try:
            user_ref = self.identity_api.get_user_by_name(user_dn,
                                                          self.domain)
        except ks_exc.UserNotFound:
            if CONF.voms.autocreate_users:
                user_ref = self._create_user(user_dn)
            else:
                LOG.debug(_("REMOTE_USER %s not found") % user_dn)
                raise

        tenant = self._get_project_from_voms(voms_info)
        # If the user is requesting a wrong tenant, stop
        if req_tenant and req_tenant != tenant["name"]:
            raise ks_exc.Unauthorized

        if CONF.voms.autocreate_users:
            tenants = self.assignment_api.list_projects_for_user(
                user_ref["id"])

            if tenant not in tenants:
                self._add_user_to_tenant(user_ref['id'], tenant['id'])

            if CONF.voms.add_roles:
                self._update_user_roles(user_ref['id'], tenant['id'])

        return user_dn, tenant['name']

    def _process_request(self, request):
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

        voms_info = self._get_voms_info(ssl_dict)

        params = request.environ.get(PARAMS_ENV)
        tenant_from_req = params["auth"].get("tenantName", None)

        user_dn, tenant = self._get_user(voms_info, tenant_from_req)

        request.environ['REMOTE_USER'] = user_dn
#        params["auth"]["tenantName"] = tenant

    def process_request(self, request):
        return self._process_request(request)
