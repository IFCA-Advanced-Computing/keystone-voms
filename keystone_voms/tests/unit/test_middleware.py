# Copyright 2016 Spanish National Research Council
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

from keystone import exception as ks_exc
from keystone.tests import unit as tests
import mock
from oslo_serialization import jsonutils
import webob

from keystone_voms import core
from keystone_voms.tests import fakes


def get_auth_body(tenant=None):
    d = {"auth": {"voms": True}}
    if tenant is not None:
        d["auth"]["tenantName"] = tenant
    return d


def make_response(**kwargs):
    body = kwargs.pop('body', None)
    return webob.Response(body)


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
        req.environ[core.PARAMS_ENV] = body
    if cert:
        req.environ[core.SSL_CLIENT_CERT_ENV] = cert
    if chain:
        req.environ[core.SSL_CLIENT_CERT_CHAIN_ENV_PREFIX + "0"] = chain
    return req


class FakeVOMS(object):
    def __init__(self, d):
        self.voname = d["voname"]
        self.fqans = d["fqans"]
        self.user = d["user"]


class MiddlewareVomsAuthn(tests.TestCase):
    def setUp(self):
        super(MiddlewareVomsAuthn, self).setUp()

    @mock.patch("__builtin__.open", mock.mock_open(read_data="{}"))
    def test_init(self):
        middleware = core.VomsAuthNMiddleware(None)
        self.assertEqual({}, middleware.voms_json)

    @mock.patch("__builtin__.open", mock.mock_open(read_data="{"))
    def test_init_invalid_json(self):
        middleware = core.VomsAuthNMiddleware(None)
        self.assertRaises(ks_exc.UnexpectedError,
                          lambda: middleware.voms_json)

    @mock.patch("__builtin__.open")
    def test_cannot_open_json_mapping(self, m_open):
        m_open.side_effect = IOError
        middleware = core.VomsAuthNMiddleware(None)
        self.assertRaises(ks_exc.UnexpectedError,
                          lambda: middleware.voms_json)

    @mock.patch("keystone_voms.core.VomsAuthNMiddleware.identity_api",
                create=True)
    @mock.patch("keystone_voms.voms.VOMS")
    @mock.patch("__builtin__.open", mock.mock_open(read_data="{}"))
    def test_middleware_proxy_unscoped_defaults(self, m_voms, m_idapi):
        m_voms.return_value = FakeVOMS(fakes.user_data["dteam"])

        m_idapi.get_user_by_name.side_effect = ks_exc.UserNotFound("fakeid")

        req = prepare_request(get_auth_body(),
                              fakes.user_proxies["dteam"],
                              fakes.user_cert)
        aux = core.VomsAuthNMiddleware(None)
        self.assertRaises(
            ks_exc.UserNotFound,
            aux.process_request,
            req)

    @mock.patch("keystone_voms.core.VomsAuthNMiddleware.identity_api",
                create=True)
    @mock.patch("keystone_voms.voms.VOMS")
    @mock.patch("__builtin__.open", mock.mock_open(read_data="{}"))
    def test_middleware_proxy_scoped_defaults(self, m_voms, m_idapi):
        m_voms.return_value = FakeVOMS(fakes.user_data["dteam"])

        m_idapi.get_user_by_name.side_effect = ks_exc.UserNotFound("fakeid")

        req = prepare_request(get_auth_body(tenant="foo"),
                              fakes.user_proxies["dteam"],
                              fakes.user_cert)
        aux = core.VomsAuthNMiddleware(None)
        self.assertRaises(
            ks_exc.UserNotFound,
            aux.process_request,
            req)

    @mock.patch("keystone_voms.core.VomsAuthNMiddleware.resource_api",
                create=True)
    @mock.patch("keystone_voms.core.VomsAuthNMiddleware.identity_api",
                create=True)
    @mock.patch("keystone_voms.voms.VOMS")
    @mock.patch("__builtin__.open", mock.mock_open(read_data="{}"))
    def test_middleware_proxy_unscoped_defaults_existing_user(self,
                                                              m_voms,
                                                              m_idapi,
                                                              m_resapi):
        m_voms.return_value = FakeVOMS(fakes.user_data["dteam"])

        m_idapi.get_user_by_name.return_value = None

        m_resapi.get_project_by_name.return_value = {"id": uuid.uuid4().hex,
                                                     "name": "BAR"}

        req = prepare_request(get_auth_body(),
                              fakes.user_proxies["dteam"],
                              fakes.user_cert)
        aux = core.VomsAuthNMiddleware(None)
        self.assertIsNone(None, aux.process_request(req))

    @mock.patch("keystone_voms.core.VomsAuthNMiddleware.resource_api",
                create=True)
    @mock.patch("keystone_voms.core.VomsAuthNMiddleware.identity_api",
                create=True)
    @mock.patch("keystone_voms.voms.VOMS")
    @mock.patch("__builtin__.open", mock.mock_open(read_data="{}"))
    def test_middleware_proxy_scoped_defaults_existing_user_bad_tenant(self,
                                                                       m_voms,
                                                                       m_idapi,
                                                                       m_rapi):
        m_voms.return_value = FakeVOMS(fakes.user_data["dteam"])
        m_idapi.get_user_by_name.return_value = None
        m_rapi.get_project_by_name.return_value = {"id": uuid.uuid4().hex,
                                                   "name": "BAR"}

        req = prepare_request(get_auth_body(tenant=uuid.uuid4().hex),
                              fakes.user_proxies["dteam"],
                              fakes.user_cert)
        aux = core.VomsAuthNMiddleware(None)
        self.assertRaises(
            ks_exc.Unauthorized,
            aux.process_request,
            req)

    @mock.patch("keystone_voms.core.VomsAuthNMiddleware.resource_api",
                create=True)
    @mock.patch("keystone_voms.core.VomsAuthNMiddleware.identity_api",
                create=True)
    @mock.patch("keystone_voms.voms.VOMS")
    @mock.patch("__builtin__.open", mock.mock_open(read_data="{}"))
    def test_middleware_proxy_scoped_defaults_existing_user(self, m_voms,
                                                            m_idapi, m_resapi):
        m_voms.return_value = FakeVOMS(fakes.user_data["dteam"])
        m_idapi.get_user_by_name.return_value = None
        m_resapi.get_project_by_name.return_value = {"id": uuid.uuid4().hex,
                                                     "name": "BAR"}

        req = prepare_request(get_auth_body(tenant="BAR"),
                              fakes.user_proxies["dteam"],
                              fakes.user_cert)
        aux = core.VomsAuthNMiddleware(None)
        self.assertIsNone(aux.process_request(req))

    @mock.patch("keystone_voms.core.VomsAuthNMiddleware.assignment_api",
                create=True)
    @mock.patch("keystone_voms.core.VomsAuthNMiddleware.resource_api",
                create=True)
    @mock.patch("keystone_voms.core.VomsAuthNMiddleware.identity_api",
                create=True)
    @mock.patch("keystone_voms.voms.VOMS")
    @mock.patch("__builtin__.open",
                mock.mock_open(read_data='{"dteam":{"tenant":"BAR"}}'))
    def test_middleware_proxy_unscoped_autocreate(self, m_voms, m_idapi,
                                                  m_resapi, m_assapi):
        self.config_fixture.config(group="voms", autocreate_users=True)

        m_voms.return_value = FakeVOMS(fakes.user_data["dteam"])

        m_idapi.get_user_by_name.side_effect = ks_exc.UserNotFound("fakeid")

        m_resapi.get_project_by_name.return_value = {"id": uuid.uuid4().hex,
                                                     "name": "BAR"}

        req = prepare_request(get_auth_body(),
                              fakes.user_proxies["dteam"],
                              fakes.user_cert)
        aux = core.VomsAuthNMiddleware(None)
        self.assertIsNone(aux.process_request(req))

    @mock.patch("keystone_voms.core.VomsAuthNMiddleware.resource_api",
                create=True)
    @mock.patch("keystone_voms.core.VomsAuthNMiddleware.identity_api",
                create=True)
    @mock.patch("keystone_voms.voms.VOMS")
    @mock.patch("__builtin__.open",
                mock.mock_open(read_data='{"dteam":{"tenant":"BAR"}}'))
    def test_middleware_proxy_unscoped_autocreate_project_not_found(self,
                                                                    m_voms,
                                                                    m_idapi,
                                                                    m_resapi):
        self.config_fixture.config(group="voms", autocreate_users=True)

        m_voms.return_value = FakeVOMS(fakes.user_data["dteam"])

        m_idapi.get_user_by_name.side_effect = ks_exc.UserNotFound("fakeid")

        m_resapi.get_project_by_name.side_effect = ks_exc.ProjectNotFound("id")

        req = prepare_request(get_auth_body(),
                              fakes.user_proxies["dteam"],
                              fakes.user_cert)
        aux = core.VomsAuthNMiddleware(None)
        aux = core.VomsAuthNMiddleware(None)
        self.assertRaises(
            ks_exc.Unauthorized,
            aux.process_request,
            req)

    @mock.patch("keystone_voms.core.VomsAuthNMiddleware.role_api", create=True)
    @mock.patch("keystone_voms.core.VomsAuthNMiddleware.assignment_api",
                create=True)
    @mock.patch("keystone_voms.core.VomsAuthNMiddleware.resource_api",
                create=True)
    @mock.patch("keystone_voms.core.VomsAuthNMiddleware.identity_api",
                create=True)
    @mock.patch("keystone_voms.voms.VOMS")
    @mock.patch("__builtin__.open",
                mock.mock_open(read_data='{"dteam":{"tenant":"BAR"}}'))
    def test_middleware_proxy_scoped_user_with_roles(self, m_voms, m_idapi,
                                                     m_resapi, m_assapi,
                                                     m_rapi):
        self.config_fixture.config(group="voms", add_roles=True)

        m_voms.return_value = FakeVOMS(fakes.user_data["dteam fqans"])

        user_id = uuid.uuid4().hex
        m_idapi.get_user_by_name.return_value = {"id": user_id}

        m_resapi.get_project_by_name.return_value = {"id": uuid.uuid4().hex,
                                                     "name": "BAR"}

        roles = [uuid.uuid4().hex]
        m_assapi.get_roles_for_user_and_project.return_value = roles

        role = {"name": "RoleFoo"}
        m_rapi.get_role.return_value = role

        req = prepare_request(get_auth_body(tenant="BAR"),
                              fakes.user_proxies["dteam fqans"],
                              fakes.user_cert)
        aux = core.VomsAuthNMiddleware(None)
        self.assertIsNone(aux.process_request(req))

    @mock.patch("keystone_voms.core.VomsAuthNMiddleware.role_api", create=True)
    @mock.patch("keystone_voms.core.VomsAuthNMiddleware.assignment_api",
                create=True)
    @mock.patch("keystone_voms.core.VomsAuthNMiddleware.resource_api",
                create=True)
    @mock.patch("keystone_voms.core.VomsAuthNMiddleware.identity_api",
                create=True)
    @mock.patch("keystone_voms.voms.VOMS")
    @mock.patch("__builtin__.open",
                mock.mock_open(read_data='{"dteam":{"tenant":"BAR"}}'))
    def test_middleware_proxy_scoped_user_with_roles_and_new_roles(self,
                                                                   m_voms,
                                                                   m_idapi,
                                                                   m_resapi,
                                                                   m_assapi,
                                                                   m_rapi):
        roles = [{"name": n, "id": uuid.uuid4().hex} for n in ("foo", "bar")]

        self.config_fixture.config(group="voms", add_roles=True)
        self.config_fixture.config(group="voms",
                                   user_roles=[r["name"] for r in roles])

        m_voms.return_value = FakeVOMS(fakes.user_data["dteam fqans"])

        user_id = uuid.uuid4().hex
        m_idapi.get_user_by_name.return_value = {"id": user_id}

        project_id = uuid.uuid4().hex
        m_resapi.get_project_by_name.return_value = {"id": project_id, "name":
                                                     "BAR"}

        user_roles = [uuid.uuid4().hex]
        m_assapi.get_roles_for_user_and_project.return_value = user_roles

        user_role = {"name": "RoleFoo"}
        m_rapi.get_role.return_value = user_role

        m_rapi.list_roles.return_value = roles

        req = prepare_request(get_auth_body(tenant="BAR"),
                              fakes.user_proxies["dteam fqans"],
                              fakes.user_cert)
        aux = core.VomsAuthNMiddleware(None)
        self.assertIsNone(aux.process_request(req))

        for r in roles:
            m_assapi.add_role_to_user_and_project.assert_any_call(user_id,
                                                                  project_id,
                                                                  r["id"])

    @mock.patch("keystone_voms.core.VomsAuthNMiddleware.role_api", create=True)
    @mock.patch("keystone_voms.core.VomsAuthNMiddleware.assignment_api",
                create=True)
    @mock.patch("keystone_voms.core.VomsAuthNMiddleware.resource_api",
                create=True)
    @mock.patch("keystone_voms.core.VomsAuthNMiddleware.identity_api",
                create=True)
    @mock.patch("keystone_voms.voms.VOMS")
    @mock.patch("__builtin__.open",
                mock.mock_open(read_data='{"dteam":{"tenant":"BAR"}}'))
    def test_middleware_proxy_scoped_user_with_roles_already_in_role(self,
                                                                     m_voms,
                                                                     m_idapi,
                                                                     m_resapi,
                                                                     m_assapi,
                                                                     m_rapi):
        self.config_fixture.config(group="voms", add_roles=True)

        m_voms.return_value = FakeVOMS(fakes.user_data["dteam"])

        user_id = uuid.uuid4().hex
        m_idapi.get_user_by_name.return_value = {"id": user_id}

        m_resapi.get_project_by_name.return_value = {"id": uuid.uuid4().hex,
                                                     "name": "BAR"}

        roles = [uuid.uuid4().hex]
        m_assapi.get_roles_for_user_and_project.return_value = roles

        role = {"name": "_member_"}
        m_rapi.get_role.return_value = role

        req = prepare_request(get_auth_body(tenant="BAR"),
                              fakes.user_proxies["dteam"],
                              fakes.user_cert)
        aux = core.VomsAuthNMiddleware(None)
        self.assertIsNone(aux.process_request(req))

    @mock.patch("__builtin__.open", mock.mock_open(read_data="{}"))
    def test_middleware_no_params(self):
        """Verify that empty request returns none."""
        req = prepare_request()
        ret = core.VomsAuthNMiddleware(None).process_request(req)
        self.assertIsNone(ret)

    @mock.patch("__builtin__.open", mock.mock_open(read_data="{}"))
    def test_middleware_remote_user_set(self):
        """Verify that if REMOTE_USER already set we skip the auth."""
        req = prepare_request()
        req.environ["REMOTE_USER"] = "Fake"
        ret = core.VomsAuthNMiddleware(None)._process_request(req)
        self.assertIsNone(ret)

    @mock.patch("__builtin__.open", mock.mock_open(read_data="{}"))
    def test_middleware_no_ssl_data_with_voms_request(self):
        """Verify that if REMOTE_USER already set we skip the auth."""
        req = prepare_request(get_auth_body())
        mdl = core.VomsAuthNMiddleware(None)
        self.assertRaises(ks_exc.ValidationError,
                          mdl._process_request,
                          req)

    @mock.patch("__builtin__.open", mock.mock_open(read_data="{}"))
    def test_middleware_should_process_response(self):
        resp = make_response(body=jsonutils.dumps({"tenants": [{}]}))
        aux = core.VomsAuthNMiddleware(None)
        self.assertTrue(aux.should_process_response(None, resp))

    @mock.patch("keystone_voms.core.VomsAuthNMiddleware.resource_api",
                create=True)
    @mock.patch("keystone_voms.voms.VOMS")
    @mock.patch("__builtin__.open", mock.mock_open(read_data="{}"))
    def test_middleware_process_response(self, m_voms, m_resapi):
        v = FakeVOMS(fakes.user_data["dteam"])
        m_voms.return_value = v

        project_id = uuid.uuid4().hex
        project = {"id": project_id, "name": "BAR"}
        m_resapi.get_project_by_name.return_value = project

        user_projects = {
            "tenants": [
                project,
                {"id": uuid.uuid4().hex}
            ]
        }
        resp = make_response(body=jsonutils.dumps(user_projects))
        aux = core.VomsAuthNMiddleware(None)
        aux.voms_obj = v
        resp = aux.process_response(None, resp)
        resp = jsonutils.loads(resp.body)
        self.assertDictEqual(project, resp["tenants"][0])

    @mock.patch("keystone_voms.core.VomsAuthNMiddleware."
                "_get_project_from_voms")
    @mock.patch("keystone_voms.core.VomsAuthNMiddleware.identity_api",
                create=True)
    @mock.patch("__builtin__.open", mock.mock_open(read_data="{}"))
    def test_get_user_pusp(self, m_idapi, m_getproject):
        req = prepare_request()
        pusp_dn = "/C=ES/O=Foo/CN=Robot: fake/CN=eToken: bar"
        v = FakeVOMS({"voname": "foo", "fqans": "bar",
                      "user": "/C=ES/O=Foo/CN=Robot: fake"})

        m_idapi.get_user_by_name.return_value = {"id": uuid.uuid4().hex}
        m_getproject.return_value = {"name": "BAR"}

        aux = core.VomsAuthNMiddleware(None)
        # pusp disabled
        user, tenant = aux._get_user(req, v, None)
        self.assertEqual(v.user, user)
        self.assertEqual("BAR", tenant)

        # pusp enabled, but no GRIDSITE var
        self.config_fixture.config(group="voms", enable_pusp=True)
        user, tenant = aux._get_user(req, v, None)
        self.assertEqual(v.user, user)
        self.assertEqual("BAR", tenant)

        # pusp enabled, with GRIDSITE var
        req.environ["GRST_CRED_AURI_1"] = ":".join(["dn", pusp_dn])
        user, tenant = aux._get_user(req, v, None)
        self.assertEqual(pusp_dn, user)
        self.assertEqual("BAR", tenant)

        # pusp enabled, with GRIDSITE var, no robot DN
        v = FakeVOMS(fakes.user_data["dteam"])
        req.environ["GRST_CRED_AURI_1"] = ":".join(["dn", pusp_dn])
        user, tenant = aux._get_user(req, v, None)
        self.assertEqual(v.user, user)
        self.assertEqual("BAR", tenant)
