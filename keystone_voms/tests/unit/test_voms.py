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

from keystone.tests import unit as tests
import mock
from OpenSSL import crypto

from keystone_voms import exception
from keystone_voms.tests import fakes
from keystone_voms import voms


class PatchedVomsContext(voms.VOMSContext):
    def __enter__(self):
        self._init_voms()
        # NOTE(aloga): This is done explicitly here, so that we do not
        # add a method for skipping verification in the VOMS class
        error = self.ffi.new("int *")
        self.lib.VOMS_SetVerificationType(0x040, self.vd, error)
        return self


class TestVOMS(tests.TestCase):
    def setUp(self):
        super(TestVOMS, self).setUp()

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

    @mock.patch("keystone_voms.voms.VOMSContext")
    def test_voms_valid(self, m_ctx):
        d = fakes.user_data["dteam"]
        m_ctx.return_value.__enter__.return_value.retrieve.return_value = d

        v = voms.VOMS(fakes.user_proxies["dteam"], fakes.user_cert)
        self.assertTrue(v.verified)

    @mock.patch("keystone_voms.voms.VOMSContext")
    def test_voms_expired(self, m_ctx):
        d = fakes.user_data["dteam"]
        m_ctx.return_value.__enter__.return_value.retrieve.return_value = d

        self.assertRaises(exception.VerifyCertificateError,
                          voms.VOMS,
                          fakes.user_proxies["dteam expired"],
                          fakes.user_cert)

    @mock.patch("keystone_voms.voms.VOMSContext")
    def test_voms_revoked_cert(self, m_ctx):
        d = fakes.user_data["dteam"]
        m_ctx.return_value.__enter__.return_value.retrieve.return_value = d

        self.m_crl.return_value = crypto.load_crl(crypto.FILETYPE_PEM,
                                                  fakes.ca_crl)

        self.assertRaises(exception.CertificateRevoked,
                          voms.VOMS,
                          fakes.user_proxies["dteam"],
                          fakes.user_cert)

    @mock.patch("keystone_voms.voms.VOMSContext")
    def test_voms_cannot_verify(self, m):
        (m.return_value.__enter__.return_value.
         retrieve.side_effect) = exception.VomsError(14)

        self.assertRaises(exception.VomsError,
                          voms.VOMS,
                          fakes.user_proxies["not-supported-vo"],
                          fakes.user_cert)


class TestVOMSContext(tests.TestCase):
    def setUp(self):
        super(TestVOMSContext, self).setUp()

        self.voms_context = PatchedVomsContext

    def test_voms_context(self):
        proxy = crypto.load_certificate(crypto.FILETYPE_PEM,
                                        fakes.user_proxies["dteam"])
        chain = crypto.X509Store()
        chain.add_cert(crypto.load_certificate(crypto.FILETYPE_PEM,
                                               fakes.user_cert))

        with self.voms_context() as vc:
            d = vc.retrieve(proxy, chain)

        expected = fakes.user_data["dteam"]
        self.assertDictEqual(expected, d)

    def test_voms_context_fqans(self):
        proxy = crypto.load_certificate(crypto.FILETYPE_PEM,
                                        fakes.user_proxies["dteam fqans"])
        chain = crypto.X509Store()
        chain.add_cert(crypto.load_certificate(crypto.FILETYPE_PEM,
                                               fakes.user_cert))

        with self.voms_context() as vc:
            d = vc.retrieve(proxy, chain)

        expected = fakes.user_data["dteam fqans"]
        self.assertDictEqual(expected, d)

    def test_voms_failure(self):
        proxy = crypto.load_certificate(crypto.FILETYPE_PEM,
                                        fakes.user_proxies["not-supported-vo"])
        chain = crypto.X509Store()
        chain.add_cert(crypto.load_certificate(crypto.FILETYPE_PEM,
                                               fakes.user_cert))

        with voms.VOMSContext() as vc:
            self.assertRaises(exception.VomsError,
                              vc.retrieve,
                              proxy, chain)
