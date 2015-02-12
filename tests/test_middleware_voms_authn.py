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

from keystone import config
from keystone import exception as ks_exc
from keystone.assignment import controllers
from keystone import middleware
from keystone import tests
from keystone.tests import default_fixtures
from keystone.tests.ksfixtures import database
from keystone.tests import test_auth
from keystone.tests import test_middleware

import keystone_voms.core as ks_voms
from  keystone_voms import exception


CONF = config.CONF

# fake proxy from a fake cert from a fake ca
user_dn = "/C=ES/O=FAKE CA/CN=Fake User"
user_vo = "dteam"
valid_cert = """-----BEGIN CERTIFICATE-----
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
W5Rbega2GkADBQ==
-----END CERTIFICATE----- """

valid_cert_chain = """-----BEGIN CERTIFICATE-----
MIIBwTCCASoCAQYwDQYJKoZIhvcNAQEEBQAwHzEQMA4GA1UEChMHRkFLRSBDQTEL
MAkGA1UEBhMCRVMwHhcNMTIwODMwMTIxMjU0WhcNNDAwMTE1MTIxMjU0WjAzMQsw
CQYDVQQGEwJFUzEQMA4GA1UEChMHRkFLRSBDQTESMBAGA1UEAxMJRmFrZSBVc2Vy
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDE4WuwYDT+ke9olzMIZ+gTwDl1
cajAIvp6jVl40YYV2CgUdQo0CSj/bmB+y6U3GCdpp0HKNoAbCuYsyyUtqedgMy2D
x+We/3f005jQvSLtrnK3k8Nw2qwkClObKhyLw5j0iH0sx0PWbr4mIcic2AY8gWiM
OshoESxjXETMkqgQpQIDAQABMA0GCSqGSIb3DQEBBAUAA4GBAA9KBCfPLuWJWKN/
X+MgdJfMtg9MbfrKwQbmoxIS7qCEe2OUNs4BvHEnp7lBMJkaoSjhvFDOFMKaXmfz
Kl441BisyU4Pz8fHU5dj4Z7pPD7i71f1oK/42kZZWFEkoJxOU4Vu/fHr9DXdrBVH
9sFWctb8TM20AtJmYE/n+M1G6Foj
-----END CERTIFICATE-----"""

valid_cert_no_tenant = """-----BEGIN CERTIFICATE-----
MIIGMDCCBZmgAwIBAgIUdvt3rmPnrq2Kyoi6oKdeSb7Ye4EwDQYJKoZIhvcNAQEF
BQAwMzELMAkGA1UEBhMCRVMxEDAOBgNVBAoTB0ZBS0UgQ0ExEjAQBgNVBAMTCUZh
a2UgVXNlcjAeFw0xMjA4MzAxNDI5NTVaFw0yNDAxMjcwNTM0NTVaMEgxCzAJBgNV
BAYTAkVTMRAwDgYDVQQKEwdGQUtFIENBMRIwEAYDVQQDEwlGYWtlIFVzZXIxEzAR
BgNVBAMTCjE3MDAwOTE3MTMwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBALgC
BIZSxt4X4Hxuapff694eHx9pjpdpfnuU5E/zuv6qNjoZn10WzngonodRG6YGjY5r
yWZm2yplAWVXuZNMD7qOo3ToeBVhl5sK8dS/dCtrCrKcAoQCAq3CdOM/cUJyDW3m
I7hYvw0BfyuOAgqZuz2trGoObHhS3HrwuNgzAYnZAgMBAAGjggQqMIIEJjCCA9gG
CisGAQQBvkVkZAUEggPIMIIDxDCCA8AwggO8MIIDJQIBATA+oDwwN6Q1MDMxCzAJ
BgNVBAYTAkVTMRAwDgYDVQQKEwdGQUtFIENBMRIwEAYDVQQDEwlGYWtlIFVzZXIC
AQagSjBIpEYwRDELMAkGA1UEBhMCRVMxEDAOBgNVBAoTB0ZBS0UgQ0ExIzAhBgNV
BAMTGmhvc3QvZmFrZS52b21zLXNlcnZlci5mYWtlMA0GCSqGSIb3DQEBBQUAAgEB
MCIYDzIwMTIwODMwMTQzNDU1WhgPMjAyNDAxMjcwNTM0NTVaMDwwOgYKKwYBBAG+
RWRkBDEsMCqgFIYSbm9fc3VwcG9ydGVkX3ZvOi8vMBIEEC9ub19zdXBwb3J0ZWRf
dm8wggIeMIIB7gYKKwYBBAG+RWRkCgSCAd4wggHaMIIB1jCCAdIwggE7AgEEMA0G
CSqGSIb3DQEBBAUAMB8xEDAOBgNVBAoTB0ZBS0UgQ0ExCzAJBgNVBAYTAkVTMB4X
DTEyMDgyOTE3MzY0OVoXDTQwMDExNDE3MzY0OVowRDELMAkGA1UEBhMCRVMxEDAO
BgNVBAoTB0ZBS0UgQ0ExIzAhBgNVBAMTGmhvc3QvZmFrZS52b21zLXNlcnZlci5m
YWtlMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC/9bo6pA8fcuo42+CDV430
nKykGB4mqsKqHkFCD8kRduW4eFdWrSXitqKRlw9/8hLmbsu5abPa/P99VekJPCbZ
wtIm+3M1qGlJ+TonTWbBQakvOmPnoLH+/uppssyRulGj61AlnR20ByRo2DbrSTTh
bdkztGOmZmQf2gzRGGtbxQIDAQABMA0GCSqGSIb3DQEBBAUAA4GBAH/gEMVvDtgN
axzH5UYRubvapReeqspS5mYndaGFaztOJQ6pv1Qa7/LpkeYOxrXX+xWmdYdXvHIY
bMkc/pO0PyV/TIOb8EcgC/Gs3idZSHUxhcsk8IcpcwCrPczpu2JC+N5zLTkbcREj
evF7WFlPMlOq2IVEIVBo95uQaS3TdmJHMAkGA1UdOAQCBQAwHwYDVR0jBBgwFoAU
MXhLHLSgWZoV/Y8KaT6VOIQNVNQwDQYJKoZIhvcNAQEFBQADgYEACztWoNeofMnd
das5pTFA8WJgrMXa8BslqM+hm/VPwA+4MoGMxQadDQGzuLSp9yMHcYzvj+Gimjs4
WZHAshZdd6E9S2hQoDRUpQguu5CNeKdJ7uUb+QQinTD6y3DjdxCFE10pFunYEMnY
2JSJbEqm32ybnFPdBBqqYlb3gXGEVQwwDQYDVR0PAQH/BAMDAQAwDAYDVR0TAQH/
BAIwADAJBgNVHSMEAjAAMCAGCCsGAQUFBwEOAQH/BBEwDwIBATAKBggrBgEFBQcV
ATANBgkqhkiG9w0BAQUFAAOBgQAQjXxCkLajAedCNqIYw1L5qlWT71sF2FgSoyEk
B7iMyweroDP90CzR1DIwWj5yGr138Z3jvDvFRzQpUrZa4hsPck/zmO/lTB+6iA/U
V5PvMZQ8wMyfMlSiFQNvWm7weNlFpvUpNRHQQj3FLb8L55RhtONIYFRzTIS9du3P
c8Dc+w==
-----END CERTIFICATE-----"""


def get_auth_body(tenant=None):
    d = {"auth": {"voms": True}}
    if tenant is not None:
        d["auth"]["tenantName"] = tenant
    return d


def prepare_request(body=None, cert=None, chain=None):
    req = test_middleware.make_request()
    if body:
        req.environ[middleware.PARAMS_ENV] = body
    if cert:
        req.environ[ks_voms.SSL_CLIENT_CERT_ENV] = cert
    if chain:
        req.environ[ks_voms.SSL_CLIENT_CERT_CHAIN_ENV_PREFIX +
                    "0"] = chain
    return req


class MiddlewareVomsAuthn(tests.TestCase):
    def setUp(self):
        super(MiddlewareVomsAuthn, self).setUp()
        self.config([tests.dirs.etc('keystone.conf.sample'),
                     tests.dirs.tests_conf('keystone_voms.conf')])
        self.useFixture(database.Database())
        self.load_backends()
        self.load_fixtures(default_fixtures)
        self.tenant_name = default_fixtures.TENANTS[0]['name']
        CONF.voms.voms_policy = tests.dirs.tests_conf("voms.json")

    def test_middleware_proxy_unscoped(self):
        """Verify unscoped request."""
        req = prepare_request(get_auth_body(),
                              valid_cert,
                              valid_cert_chain)
        aux = ks_voms.VomsAuthNMiddleware(None)
        aux._no_verify = True
        aux._process_request(req)
        user_out = req.environ['REMOTE_USER']
        params = req.environ[middleware.PARAMS_ENV]
        self.assertEqual(user_out, user_dn)
        self.assertNotIn("tenantName", params)

    def test_middleware_proxy_scoped(self):
        """Verify scoped request."""
        req = prepare_request(get_auth_body(tenant=self.tenant_name),
                              valid_cert,
                              valid_cert_chain)
        aux = ks_voms.VomsAuthNMiddleware(None)
        aux._no_verify = True
        aux._process_request(req)
        user_out = req.environ['REMOTE_USER']
        self.assertEqual(user_out, user_dn)

    def test_middleware_proxy_scoped_bad_tenant(self):
        """Verify request not matching tenant."""
        req = prepare_request(get_auth_body(tenant=uuid.uuid4().hex),
                              valid_cert,
                              valid_cert_chain)
        aux = ks_voms.VomsAuthNMiddleware(None)
        aux._no_verify = True
        self.assertRaises(
            ks_exc.Unauthorized,
            aux._process_request,
            req)

    def test_middleware_proxy_tenant_not_found(self):
        """Verify that mapping to a non existing tenant raises ks_exc."""
        CONF.voms.voms_policy = tests.dirs.tests_conf("voms_no_tenant.json")
        req = prepare_request(get_auth_body(tenant=self.tenant_name),
                              valid_cert,
                              valid_cert_chain)
        aux = ks_voms.VomsAuthNMiddleware(None)
        aux._no_verify = True
        self.assertRaises(
            ks_exc.Unauthorized,
            aux._process_request,
            req)

    def test_middleware_proxy_vo_not_found(self):
        """Verify that no VO-tenant mapping raises ks_exc."""
        CONF.voms.voms_policy = tests.dirs.tests_conf("voms_no_vo.json")
        req = prepare_request(get_auth_body(tenant=self.tenant_name),
                              valid_cert,
                              valid_cert_chain)
        aux = ks_voms.VomsAuthNMiddleware(None)
        aux._no_verify = True
        self.assertRaises(
            ks_exc.Unauthorized,
            aux._process_request,
            req)

    def test_middleware_proxy_vo_not_found_unscoped(self):
        """Verify that no VO-tenant mapping raises ks_exc."""
        CONF.voms.voms_policy = tests.dirs.tests_conf("voms_no_vo.json")
        req = prepare_request(get_auth_body(tenant=self.tenant_name),
                              valid_cert,
                              valid_cert_chain)
        aux = ks_voms.VomsAuthNMiddleware(None)
        aux._no_verify = True
        self.assertRaises(
            ks_exc.Unauthorized,
            aux._process_request,
            req)

    def test_middleware_proxy_user_not_found_autocreate(self):
        """Verify that user is autocreated."""
        CONF.voms.autocreate_users = True
        req = prepare_request(get_auth_body(tenant=self.tenant_name),
                              valid_cert,
                              valid_cert_chain)
        aux = ks_voms.VomsAuthNMiddleware(None)
        aux._no_verify = True
        aux._process_request(req)
        user_out = req.environ['REMOTE_USER']
        self.assertEqual(user_out, user_dn)

    def test_middleware_proxy_user_not_found_autocreate_once(self):
        """Verify that user is autocreated only once."""
        CONF.voms.autocreate_users = True
        req = prepare_request(get_auth_body(tenant=self.tenant_name),
                              valid_cert,
                              valid_cert_chain)

        aux = ks_voms.VomsAuthNMiddleware(None)
        aux._no_verify = True
        aux._process_request(req)
        user_out = req.environ['REMOTE_USER']
        self.assertEqual(user_out, user_dn)

        req = prepare_request(get_auth_body(tenant=self.tenant_name),
                              valid_cert,
                              valid_cert_chain)
        aux._process_request(req)
        user_out = req.environ['REMOTE_USER']
        self.assertEqual(user_out, user_dn)

    def test_middleware_proxy_user_not_found_autocreate_unscoped(self):
        """Verify that user is autocreated with unscoped request."""
        CONF.voms.autocreate_users = True
        req = prepare_request(get_auth_body(),
                              valid_cert,
                              valid_cert_chain)
        aux = ks_voms.VomsAuthNMiddleware(None)
        aux._no_verify = True
        aux._process_request(req)
        user_out = req.environ['REMOTE_USER']
        self.assertEqual(user_out, user_dn)

    def test_middleware_proxy_user_not_found_autocreate_chain(self):
        """Verify that an unscoped req creates the user in the tenant."""
        CONF.voms.autocreate_users = True
        req = prepare_request(get_auth_body(tenant=self.tenant_name),
                              valid_cert,
                              valid_cert_chain)
        aux = ks_voms.VomsAuthNMiddleware(None)
        aux._no_verify = True
        aux._process_request(req)
        user_out = req.environ['REMOTE_USER']
        self.assertEqual(user_out, user_dn)
        # Ensure that we are geting the user already created
        CONF.voms.autocreate_users = False
        req = prepare_request(get_auth_body(tenant=self.tenant_name),
                              valid_cert,
                              valid_cert_chain)
        aux = ks_voms.VomsAuthNMiddleware(None)
        aux._no_verify = True
        aux._process_request(req)
        user_out = req.environ['REMOTE_USER']
        self.assertEqual(user_out, user_dn)

    def test_middleware_proxy_user_not_found_not_autocreate(self):
        """Verify that user is not autocreated."""
        CONF.voms.autocreate_users = False
        req = prepare_request(get_auth_body(),
                              valid_cert,
                              valid_cert_chain)
        aux = ks_voms.VomsAuthNMiddleware(None)
        aux._no_verify = True
        self.assertRaises(
            ks_exc.UserNotFound,
            aux._process_request,
            req)

    def test_middleware_proxy_user_not_found_not_autocreate_unscoped(self):
        """Verify that user is not autocreated with unscoped request."""
        CONF.voms.autocreate_users = False
        req = prepare_request(get_auth_body(tenant=self.tenant_name),
                              valid_cert,
                              valid_cert_chain)
        aux = ks_voms.VomsAuthNMiddleware(None)
        aux._no_verify = True
        self.assertRaises(
            ks_exc.UserNotFound,
            aux._process_request,
            req)

    def test_middleware_proxy_unknown(self):
        """Verify that an unknown proxy raises ks_exc."""
        req = prepare_request(get_auth_body(),
                              valid_cert,
                              valid_cert_chain)
        self.assertRaises(
            exception.VomsError,
            ks_voms.VomsAuthNMiddleware(None)._process_request,
            req)

    def test_middleware_no_proxy(self):
        """Verify that no proxy raises ks_exc."""
        req = prepare_request()
        req.environ[middleware.PARAMS_ENV] = get_auth_body()
        self.assertRaises(
            ks_exc.ValidationError,
            ks_voms.VomsAuthNMiddleware(None)._process_request,
            req)

    def test_middleware_incorrect_json(self):
        """Verify that bad JSON raises ks_exc."""
        req = prepare_request()
        req.environ[middleware.PARAMS_ENV] = {"auth": {"voms": "True"}}
        self.assertRaises(
            ks_exc.ValidationError,
            ks_voms.VomsAuthNMiddleware(None)._process_request,
            req)

    def test_middleware_no_params(self):
        """Verify that empty request returns none."""
        req = prepare_request()
        ret = ks_voms.VomsAuthNMiddleware(None)._process_request(req)
        self.assertIsNone(ret)

    def test_middleware_remote_user_set(self):
        """Verify that if REMOTE_USER already set we skip the auth."""
        req = prepare_request()
        req.environ["REMOTE_USER"] = "Fake"
        ret = ks_voms.VomsAuthNMiddleware(None)._process_request(req)
        self.assertIsNone(ret)

    def test_no_json_data(self):
        """Verify that no JSON data raises ks_exc."""
        CONF.voms.voms_policy = None
        self.assertRaises(
            ks_exc.UnexpectedError,
            ks_voms.VomsAuthNMiddleware,
            None)


class VomsTokenService(test_auth.AuthTest):
    def setUp(self):
        super(VomsTokenService, self).setUp()
        self.config([tests.dirs.etc('keystone.conf.sample'),
                     tests.dirs.tests_conf('keystone_voms.conf')])
        self.tenant_name = default_fixtures.TENANTS[0]['name']
        self.tenant_id = default_fixtures.TENANTS[0]['id']
        CONF.voms.voms_policy = tests.dirs.tests_conf("voms.json")

    def test_unscoped_remote_authn(self):
        """Verify unscoped request."""
        req = prepare_request(get_auth_body(),
                              valid_cert,
                              valid_cert_chain)
        aux = ks_voms.VomsAuthNMiddleware(None)
        aux._no_verify = True
        aux._process_request(req)
        params = req.environ[middleware.PARAMS_ENV]
        context = {"environment": req.environ}
        remote_token = self.controller.authenticate(context,
                                                    params["auth"])
        self.assertEqual(user_dn, remote_token["access"]["user"]["username"])
        self.assertNotIn("tenant", remote_token["access"])

    def test_unscoped_remote_authn_existing_user_in_tenant(self):
        """Verify unscoped request for existing user, already in a tenant."""

        user = {
            "name": user_dn,
            "enabled": True,
            "domain_id": default_fixtures.DEFAULT_DOMAIN_ID,
        }
        tenant_id = default_fixtures.TENANTS[-1]["id"]

        # Create the user
        user = self.identity_api.create_user(user)
        # Add the user to tenant different than the mapped one
        self.assignment_api.add_user_to_project(tenant_id, user["id"])
        req = prepare_request(get_auth_body(),
                              valid_cert,
                              valid_cert_chain)
        aux = ks_voms.VomsAuthNMiddleware(None)
        aux._no_verify = True
        aux._process_request(req)
        params = req.environ[middleware.PARAMS_ENV]
        context = {"environment": req.environ}
        remote_token = self.controller.authenticate(context,
                                                    params["auth"])

        tenant_controller = controllers.Tenant()
        fake_context = {
            "token_id": remote_token["access"]["token"]["id"],
            "query_string": {"limit": None},
        }
        tenants = tenant_controller.get_projects_for_token(fake_context)
        self.assertItemsEqual(
            (self.tenant_id, tenant_id),  # User tenants
            [i["id"].lower() for i in tenants["tenants"]]
        )

    def test_scoped_remote_authn(self):
        """Verify unscoped request."""
        req = prepare_request(get_auth_body(tenant=self.tenant_name),
                              valid_cert,
                              valid_cert_chain)
        aux = ks_voms.VomsAuthNMiddleware(None)
        aux._no_verify = True
        aux._process_request(req)
        params = req.environ[middleware.PARAMS_ENV]
        context = {"environment": req.environ}
        remote_token = self.controller.authenticate(context,
                                                    params["auth"])
        self.assertEqual(user_dn,
                         remote_token["access"]["user"]["username"])
        self.assertEqual(self.tenant_name,
                         remote_token["access"]["token"]["tenant"]["name"])

    def test_scoped_remote_authn_add_roles_created_user(self):
        """Verify roles are added when user is created on authentication."""
        CONF.voms.add_roles = True
        CONF.voms.user_roles = ["role1", "role2"]
        req = prepare_request(get_auth_body(tenant=self.tenant_name),
                              valid_cert,
                              valid_cert_chain)
        aux = ks_voms.VomsAuthNMiddleware(None)
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
            "name": user_dn,
            "enabled": True,
            "domain_id": default_fixtures.DEFAULT_DOMAIN_ID,
        }
        self.identity_api.create_user(user)
        req = prepare_request(get_auth_body(tenant=self.tenant_name),
                              valid_cert,
                              valid_cert_chain)
        aux = ks_voms.VomsAuthNMiddleware(None)
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
            "name": user_dn,
            "enabled": True,
            "domain_id": default_fixtures.DEFAULT_DOMAIN_ID,
        }
        # Create the user and add to tenant
        user = self.identity_api.create_user(user)
        self.assignment_api.add_user_to_project(self.tenant_id, user["id"])
        # create roles and add them to user
        for r in CONF.voms.user_roles:
            self.assignment_api.create_role(r, {'id': r, 'name': r})
            self.assignment_api.add_role_to_user_and_project(user["id"],
                                                             self.tenant_id,
                                                             r)
        req = prepare_request(get_auth_body(tenant=self.tenant_name),
                              valid_cert,
                              valid_cert_chain)
        aux = ks_voms.VomsAuthNMiddleware(None)
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
                              valid_cert,
                              valid_cert_chain)
        aux = ks_voms.VomsAuthNMiddleware(None)
        aux._no_verify = True
        aux._process_request(req)
        params = req.environ[middleware.PARAMS_ENV]
        context = {"environment": req.environ}
        remote_token = self.controller.authenticate(context,
                                                    params["auth"])
        roles = [r['name'] for r in remote_token['access']['user']['roles']]
        self.assertNotIn("role1", roles)
        self.assertNotIn("role2", roles)
