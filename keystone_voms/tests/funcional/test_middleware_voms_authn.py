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

import os.path

from keystone.assignment import controllers
from keystone.common import authorization
from keystone.common import config
from keystone import middleware
from keystone.models import token_model
from keystone.tests.unit import default_fixtures
from keystone.tests.unit import test_auth
import mock
from OpenSSL import crypto
import webob

from keystone_voms import core
from keystone_voms.tests import fakes
from keystone_voms import voms


CONF = config.CONF


def get_auth_body(tenant=None):
    d = {"auth": {"voms": True}}
    if tenant is not None:
        d["auth"]["tenantName"] = tenant
    return d


def make_request(**kwargs):
    accept = kwargs.pop('accept', None)
    method = kwargs.pop('method', 'GET')
    body = kwargs.pop('body', None)
    req = webob.Request.blank('/', **kwargs)
    req.method = method
    if body is not None:
        req.body = body
    if accept is not None:
        req.accept = accept
    return req


def prepare_request(body=None, cert=None, chain=None):
    req = make_request()
    if body:
        req.environ[middleware.PARAMS_ENV] = body
    if cert:
        req.environ[core.SSL_CLIENT_CERT_ENV] = cert
    if chain:
        req.environ[core.SSL_CLIENT_CERT_CHAIN_ENV_PREFIX + "0"] = chain
    return req


TESTSDIR = os.path.dirname(os.path.abspath(__file__))
TESTCONF = os.path.join(TESTSDIR, 'config_files')
ROOTDIR = os.path.normpath(os.path.join(TESTSDIR, '..', '..', '..'))
VENDOR = os.path.join(ROOTDIR, 'vendor')
ETCDIR = os.path.join(ROOTDIR, 'etc')


class dirs(object):
    @staticmethod
    def root(*p):
        return os.path.join(ROOTDIR, *p)

    @staticmethod
    def etc(*p):
        return os.path.join(ETCDIR, *p)

    @staticmethod
    def tests(*p):
        return os.path.join(TESTSDIR, *p)

    @staticmethod
    def tests_conf(*p):
        return os.path.join(TESTCONF, *p)


class PatchedVomsContext(voms.VOMSContext):
    def __enter__(self):
        self._init_voms()
        # NOTE(aloga): This is done explicitly here, so that we do not
        # add a method for skipping verification in the VOMS class
        error = self.ffi.new("int *")
        self.lib.VOMS_SetVerificationType(0x040, self.vd, error)
        return self


class VomsTokenService(test_auth.AuthTest):
    def setUp(self):
        super(VomsTokenService, self).setUp()
        self.config([dirs.tests_conf('keystone_voms.conf')])
        self.tenant_name = default_fixtures.TENANTS[0]['name']
        self.tenant_id = default_fixtures.TENANTS[0]['id']
        CONF.voms.voms_policy = dirs.tests_conf("voms.json")
        self.aux_tenant_name = default_fixtures.TENANTS[1]['name']

        context_patcher = mock.patch("keystone_voms.voms.VOMSContext",
                                     PatchedVomsContext)
        self.m_context = context_patcher.start()
        self.addCleanup(context_patcher.stop)

        crl_patcher = mock.patch("keystone_voms.voms.VOMS._load_crl")
        self.m_crl = crl_patcher.start()
        self.m_crl.return_value = crypto.load_crl(crypto.FILETYPE_PEM,
                                                  fakes.ca_empty_crl)
        self.addCleanup(crl_patcher.stop)

        ca_patcher = mock.patch("keystone_voms.voms.VOMS._load_ca")
        self.m_ca = ca_patcher.start()
        self.m_ca.return_value = crypto.load_certificate(crypto.FILETYPE_PEM,
                                                         fakes.ca)
        self.addCleanup(ca_patcher.stop)

    def test_unscoped_remote_authn(self):
        """Verify unscoped request."""
        req = prepare_request(get_auth_body(),
                              fakes.user_proxies["dteam"],
                              fakes.user_cert)
        aux = core.VomsAuthNMiddleware(None)
        aux._process_request(req)
        params = req.environ[middleware.PARAMS_ENV]
        context = {"environment": req.environ}
        remote_token = self.controller.authenticate(context,
                                                    params["auth"])
        self.assertEqual(fakes.user_dn,
                         remote_token["access"]["user"]["username"])
        self.assertNotIn("tenant", remote_token["access"])

    def test_unscoped_remote_authn_existing_user_in_tenant(self):
        """Verify unscoped request for existing user, already in a tenant."""

        user = {
            "name": fakes.user_dn,
            "enabled": True,
            "domain_id": default_fixtures.DEFAULT_DOMAIN_ID,
        }
        tenant_id = default_fixtures.TENANTS[-1]["id"]

        # Create the user
        user = self.identity_api.create_user(user)
        # Add the user to tenant different than the mapped one
        self.assignment_api.add_user_to_project(tenant_id, user["id"])
        req = prepare_request(get_auth_body(),
                              fakes.user_proxies["dteam"],
                              fakes.user_cert)
        aux = core.VomsAuthNMiddleware(None)
        aux._no_verify = True
        aux._process_request(req)
        params = req.environ[middleware.PARAMS_ENV]
        context = {"environment": req.environ}
        remote_token = self.controller.authenticate(context,
                                                    params["auth"])

        tenant_controller = controllers.TenantAssignment()

        token_id = remote_token["access"]["token"]["id"]
        token_ref = token_model.KeystoneToken(token_id=token_id,
                                              token_data=remote_token)
        auth_context = authorization.token_to_auth_context(token_ref)
        fake_context = {
            "environment": {authorization.AUTH_CONTEXT_ENV: auth_context},
            "token_id": token_id,
            "query_string": {"limit": None},
        }

        tenants = tenant_controller.get_projects_for_token(fake_context)
        self.assertItemsEqual(
            (self.tenant_id, tenant_id),  # User tenants
            [i["id"].lower() for i in tenants["tenants"]]
        )

    def test_scoped_remote_authn(self):
        """Verify scoped request."""
        req = prepare_request(get_auth_body(tenant=self.tenant_name),
                              fakes.user_proxies["dteam"],
                              fakes.user_cert)
        aux = core.VomsAuthNMiddleware(None)
        aux._no_verify = True
        aux._process_request(req)
        params = req.environ[middleware.PARAMS_ENV]
        context = {"environment": req.environ}
        remote_token = self.controller.authenticate(context,
                                                    params["auth"])
        self.assertEqual(fakes.user_dn,
                         remote_token["access"]["user"]["username"])
        self.assertEqual(self.tenant_name,
                         remote_token["access"]["token"]["tenant"]["name"])

    def test_scoped_remote_authn_add_roles_created_user(self):
        """Verify roles are added when user is created on authentication."""
        CONF.voms.add_roles = True
        CONF.voms.user_roles = ["role1", "role2"]
        req = prepare_request(get_auth_body(tenant=self.tenant_name),
                              fakes.user_proxies["dteam"],
                              fakes.user_cert)
        aux = core.VomsAuthNMiddleware(None)
        aux._no_verify = True
        aux._process_request(req)
        params = req.environ[middleware.PARAMS_ENV]
        context = {"environment": req.environ}
        remote_token = self.controller.authenticate(context,
                                                    params["auth"])
        roles = [r['name'] for r in remote_token['access']['user']['roles']]
        self.assertIn("role1", roles)
        self.assertIn("role2", roles)

    def test_scoped_remote_authn_add_roles_existing_user(self):
        """Verify roles are updated for existing user."""
        CONF.voms.add_roles = True
        CONF.voms.user_roles = ["role1", "role2"]
        user = {
            "name": fakes.user_dn,
            "enabled": True,
            "domain_id": default_fixtures.DEFAULT_DOMAIN_ID,
        }
        self.identity_api.create_user(user)
        req = prepare_request(get_auth_body(tenant=self.tenant_name),
                              fakes.user_proxies["dteam"],
                              fakes.user_cert)
        aux = core.VomsAuthNMiddleware(None)
        aux._no_verify = True
        aux._process_request(req)
        params = req.environ[middleware.PARAMS_ENV]
        context = {"environment": req.environ}
        remote_token = self.controller.authenticate(context,
                                                    params["auth"])
        roles = [r['name'] for r in remote_token['access']['user']['roles']]
        self.assertIn("role1", roles)
        self.assertIn("role2", roles)

    def test_scoped_remote_authn_update_roles_existing_user(self):
        """Verify roles are not re-added to existing user."""
        CONF.voms.add_roles = True
        CONF.voms.user_roles = ["role1", "role2"]
        user = {
            "name": fakes.user_dn,
            "enabled": True,
            "domain_id": default_fixtures.DEFAULT_DOMAIN_ID,
        }
        # Create the user and add to tenant
        user = self.identity_api.create_user(user)
        self.assignment_api.add_user_to_project(self.tenant_id, user["id"])
        # create roles and add them to user
        for r in CONF.voms.user_roles:
            self.role_api.create_role(r, {'id': r, 'name': r})
            self.assignment_api.add_role_to_user_and_project(user["id"],
                                                             self.tenant_id,
                                                             r)
        req = prepare_request(get_auth_body(tenant=self.tenant_name),
                              fakes.user_proxies["dteam"],
                              fakes.user_cert)
        aux = core.VomsAuthNMiddleware(None)
        aux._no_verify = True
        aux._process_request(req)
        params = req.environ[middleware.PARAMS_ENV]
        context = {"environment": req.environ}
        remote_token = self.controller.authenticate(context,
                                                    params["auth"])
        roles = [r['name'] for r in remote_token['access']['user']['roles']]
        self.assertIn("role1", roles)
        self.assertIn("role2", roles)

    def test_scoped_remote_authn_add_roles_disabled(self):
        """Verify plugin does not try to add roles to user if disabled."""
        CONF.voms.add_roles = False
        CONF.voms.user_roles = ["role1", "role2"]
        req = prepare_request(get_auth_body(tenant=self.tenant_name),
                              fakes.user_proxies["dteam"],
                              fakes.user_cert)
        aux = core.VomsAuthNMiddleware(None)
        aux._no_verify = True
        aux._process_request(req)
        params = req.environ[middleware.PARAMS_ENV]
        context = {"environment": req.environ}
        remote_token = self.controller.authenticate(context,
                                                    params["auth"])
        roles = [r['name'] for r in remote_token['access']['user']['roles']]
        self.assertNotIn("role1", roles)
        self.assertNotIn("role2", roles)

    def test_user_tenants_filter_by_vo(self):
        """Verify that multiple tenants are filtered out."""
        CONF.voms.voms_policy = dirs.tests_conf("voms_multiple_vos.json")

        # first request with dteam proxy
        req_dteam = prepare_request(get_auth_body(),
                                    fakes.user_proxies["dteam"],
                                    fakes.user_cert)
        aux = core.VomsAuthNMiddleware(None)
        aux._no_verify = True
        aux._process_request(req_dteam)
        params = req_dteam.environ[middleware.PARAMS_ENV]
        context = {"environment": req_dteam.environ}
        remote_token = self.controller.authenticate(context,
                                                    params["auth"])
        tenant_controller = controllers.TenantAssignment()
        token_id = remote_token["access"]["token"]["id"]
        token_ref = token_model.KeystoneToken(token_id=token_id,
                                              token_data=remote_token)
        auth_context = authorization.token_to_auth_context(token_ref)
        fake_context = {
            "environment": {authorization.AUTH_CONTEXT_ENV: auth_context},
            "token_id": token_id,
            "query_string": {"limit": None},
        }
        tenants = tenant_controller.get_projects_for_token(fake_context)
        dteam_tenants = aux._filter_tenants(tenants["tenants"])
        self.assertEqual(self.tenant_name, dteam_tenants[0]["name"])

        # repeat with other VO
        req_ops = prepare_request(get_auth_body(),
                                  fakes.user_proxies["ops"],
                                  fakes.user_cert)
        aux._process_request(req_ops)
        params = req_dteam.environ[middleware.PARAMS_ENV]
        context = {"environment": req_dteam.environ}
        remote_token = self.controller.authenticate(context,
                                                    params["auth"])
        tenant_controller = controllers.TenantAssignment()
        token_id = remote_token["access"]["token"]["id"]
        token_ref = token_model.KeystoneToken(token_id=token_id,
                                              token_data=remote_token)
        auth_context = authorization.token_to_auth_context(token_ref)
        fake_context = {
            "environment": {authorization.AUTH_CONTEXT_ENV: auth_context},
            "token_id": token_id,
            "query_string": {"limit": None},
        }
        tenants = tenant_controller.get_projects_for_token(fake_context)
        # user should be now in two tenants
        self.assertEqual(2, len(tenants["tenants"]))
        ops_tenants = aux._filter_tenants(tenants["tenants"])
        # check that is correctly filtered out
        self.assertEqual(1, len(ops_tenants))
        self.assertEqual(self.aux_tenant_name, ops_tenants[0]["name"])
