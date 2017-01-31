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

import copy
import re
import uuid

from keystone.common import dependency
from keystone.common import wsgi
from keystone import exception as ks_exc
from keystone.i18n import _
import keystone.middleware
from oslo_config import cfg
from oslo_log import log
from oslo_serialization import jsonutils
from six.moves import urllib

from keystone_voms import voms

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
    cfg.BoolOpt("enable_pusp",
                default=False,
                help="If enabled, PUSP users from robot certificates "
                     "will be handled as independent users (Requires "
                     "gridproxy module)."),
]
CONF.register_opts(opts, group="voms")

PARAMS_ENV = keystone.middleware.PARAMS_ENV
CONTEXT_ENV = keystone.middleware.CONTEXT_ENV

SSL_CLIENT_S_DN_ENV = "SSL_CLIENT_S_DN"
SSL_CLIENT_CERT_ENV = "SSL_CLIENT_CERT"
SSL_CLIENT_CERT_CHAIN_ENV_PREFIX = "SSL_CLIENT_CERT_CHAIN_"

ROBOT_PROXY_REGEXP = r'^(\/.+)/CN=[Rr]obot[^\w\\]+([^\/]+)$'
PUSP_REGEXP = r'^(\/.+)/CN=[Rr]obot[^\w\\]+([^\/]+)/CN=eToken:([^\/]+)$'


@dependency.requires('identity_api', 'assignment_api', 'resource_api',
                     'role_api')
class VomsAuthNMiddleware(wsgi.Middleware):
    """Filter that checks for the SSL data in the request.

    Sets 'ssl' in the context as a dictionary containing this data.
    """
    def __init__(self, *args, **kwargs):
        self.domain = CONF.identity.default_domain_id or "default"

        self._voms_json = None

        super(VomsAuthNMiddleware, self).__init__(*args, **kwargs)

    @property
    def voms_json(self):
        if self._voms_json is None:
            try:
                self._voms_json = jsonutils.loads(
                    open(CONF.voms.voms_policy).read())
            except ValueError:
                raise ks_exc.UnexpectedError("Bad formatted VOMS json data "
                                             "from %s" % CONF.voms.voms_policy)
            except Exception:
                raise ks_exc.ConfigFileNotFound(
                    config_file=CONF.voms.voms_policy)
        return self._voms_json

    @staticmethod
    def _split_fqan(fqan):
        """Splits a FQAN into VO/groups, roles and capability.

        returns a tuple containing
        (vo/groups, role, capability)
        """
        l = fqan.split("/")
        capability = l.pop().split("=")[-1]
        role = l.pop().split("=")[-1]
        vogroup = "/".join(l)
        return (vogroup, role, capability)

    def is_applicable(self, request):
        """Check if the module should be applicable to the request."""
        if request.environ.get('REMOTE_USER', None) is not None:
            # authenticated upstream
            return False

        params = request.environ.get(PARAMS_ENV, {})
        auth = params.get("auth", {})
        if "voms" in auth:
            if auth["voms"] is True:
                return True
            else:
                raise ks_exc.ValidationError("Error in JSON, 'voms' "
                                             "must be set to true")
        return False

    def should_process_response(self, request, response):
        """Check if the response should be processed or not."""
        try:
            if response.json_body.get("tenants"):
                return True
        except (ValueError, AttributeError):
            pass
        return False

    def _get_project_from_voms(self, voms_obj):
        user_vo = voms_obj.voname
        user_fqans = voms_obj.fqans
        voinfo = None
        for fqan in user_fqans:
            voinfo = self.voms_json.get(fqan, {})
            if voinfo is not {}:
                break
        # If no FQAN matched, try with the VO name
        if not voinfo:
            voinfo = self.voms_json.get(user_vo, {})

        tenant_name = voinfo.get("tenant", "")

        try:
            tenant_ref = self.resource_api.get_project_by_name(tenant_name,
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
        LOG.info(_("Automatically adding user %(user)s to tenant %(tenant)s")
                 % {"user": user_id, "tenant": tenant_id})
        self.assignment_api.add_user_to_project(tenant_id, user_id)

    def _search_role(self, r_name):
        for role in self.role_api.list_roles():
            if role.get('name') == r_name:
                return role
        return None

    def _update_user_roles(self, user_id, tenant_id):
        # getting the role names is not straightforward
        # a get_role_by_name would be useful
        user_roles = self.assignment_api.get_roles_for_user_and_project(
            user_id, tenant_id)
        role_names = [self.role_api.get_role(role_id).get('name')
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
                self.role_api.create_role(r_id, role)
            LOG.debug(_("Adding role '%s' to user") % r_name)
            self.assignment_api.add_role_to_user_and_project(user_id,
                                                             tenant_id,
                                                             role['id'])

    def _get_user(self, request, voms_obj, req_tenant):
        user_dn = voms_obj.user
        if CONF.voms.enable_pusp and re.match(ROBOT_PROXY_REGEXP, user_dn):
            robot_dn = urllib.parse.unquote(
                request.environ.get("GRST_CRED_AURI_1", "")[3:])
            if re.match(PUSP_REGEXP, robot_dn):
                user_dn = robot_dn
        try:
            user_ref = self.identity_api.get_user_by_name(user_dn,
                                                          self.domain)
        except ks_exc.UserNotFound:
            if CONF.voms.autocreate_users:
                user_ref = self._create_user(user_dn)
            else:
                LOG.debug(_("REMOTE_USER %s not found") % user_dn)
                raise

        tenant = self._get_project_from_voms(voms_obj)
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
        if not self.is_applicable(request):
            return self.application

        proxy = request.environ.get(SSL_CLIENT_CERT_ENV, None)
        keys = request.environ.keys()
        keys.sort()
        chain = [request.environ[k] for k in keys
                 if k.startswith(SSL_CLIENT_CERT_CHAIN_ENV_PREFIX)]

        if not (proxy and chain):
            raise ks_exc.ValidationError(
                attribute="X.509 Proxy Certificate",
                target=CONTEXT_ENV)

        voms_obj = voms.VOMS(proxy, chain,
                             vomsdir_path=CONF.voms.vomsdir_path,
                             ca_path=CONF.voms.ca_path)

        params = request.environ.get(PARAMS_ENV)
        req_tenant = params["auth"].get("tenantName", None)

        user_dn, tenant = self._get_user(request, voms_obj, req_tenant)

        request.environ['REMOTE_USER'] = user_dn

        self.voms_obj = voms_obj

    def process_request(self, request):
        return self._process_request(request)

    def _filter_tenants(self, tenants):
        tenant = self._get_project_from_voms(self.voms_obj)
        return [t for t in tenants if t['id'] == tenant['id']]

    def process_response(self, request, response):
        if not self.should_process_response(request, response):
            return response

        json_body = copy.copy(response.json)
        json_body["tenants"] = self._filter_tenants(json_body["tenants"])
        response.body = jsonutils.dumps(json_body)
        return response
