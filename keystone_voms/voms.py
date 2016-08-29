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

import os

import cffi
from OpenSSL._util import lib as _lib
from OpenSSL import crypto

from keystone_voms import exception

os.environ["OPENSSL_ALLOW_PROXY_CERTS"] = "1"


class VOMS(object):
    """Object handling VOMS information.

    A VOMS object can be used for accessing the information carried out
    by a VOMS proxy. If the verification fails, or if the VOMS cannot be
    retrieved, exceptions will be raised, therefore the object wold not be
    created.
    """

    def __init__(self, cert, chain,
                 vomsdir_path='/etc/grid-security/vomsdir',
                 ca_path='/etc/grid-security/certificates'):

        self.vomsdir_path = vomsdir_path
        self.ca_path = ca_path

        self.proxy = crypto.load_certificate(crypto.FILETYPE_PEM, cert)

        if not isinstance(chain, list):
            chain = [chain]

        self.chain = []

        self.chain_store = crypto.X509Store()
        for cert in chain:
            cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert)
            self.chain.append(cert)
            self.chain_store.add_cert(cert)

        self.ssldepth = 10

        self.user = None
        self.userca = None
        self.server = None
        self.serverca = None
        self.voname = None
        self.uri = None
        self.serial = None
        self.not_before = None
        self.not_after = None
        self.fqans = None

        try:
            self._retrieve()
            self._verify()
            self._check_crl()
        except Exception:
            raise
        else:
            self.verified = True

    def _retrieve(self):
        with VOMSContext(vomsdir_path=self.vomsdir_path,
                         ca_path=self.ca_path) as v:
            d = v.retrieve(self.proxy, self.chain_store)

        self.user = d["user"]
        self.userca = d["userca"]
        self.server = d["server"]
        self.serverca = d["serverca"]
        self.voname = d["voname"]
        self.uri = d["uri"]
        self.serial = d["serial"]
        self.not_before = d["not_before"]
        self.not_after = d["not_after"]
        self.fqans = d["fqans"]

    def __repr__(self):
        rep = ("<VOMS user:%s ca:%s VO:%s FQANS:%s verified:%s>" %
               (self.user, self.userca, self.voname,
                   self.fqans, self.verified))
        return rep

    def _load_openssl_file(self, ssl_hash, kind):
        if kind == "ca":
            suffix = "0"
            fn = crypto.load_certificate
        else:
            suffix = "r0"
            fn = crypto.load_crl

        # NOTE(aloga): filename is 8 characters long
        ssl_file = os.path.join(self.ca_path, "%s.%s" %
                                (ssl_hash.zfill(8), suffix))
        try:
            with open(ssl_file, "r") as f:
                obj = fn(crypto.FILETYPE_PEM, f.read())
        except Exception as e:
            raise exception.FileError(file=ssl_file, reason=e)
        except crypto.Error as e:
            raise exception.SSLLoadError(file=ssl_file, reason=e)
        else:
            return obj

    def _load_ca(self, ca_hash):
        return self._load_openssl_file(ca_hash, kind="ca")

    def _load_crl(self, crl_hash):
        return self._load_openssl_file(crl_hash, kind="crl")

    def _get_issuer_cert(self, cert):
        h = format(int(cert.get_issuer().hash()), "02x")
        issuer_cert = self._load_ca(h)
        return issuer_cert

    def _verify(self):
        store_ctx = crypto.X509StoreContext(self.chain_store, self.proxy)
        issuer_cert = self.chain[-1]
        depth = 0
        while depth < self.ssldepth:
            if issuer_cert.get_issuer() == issuer_cert.get_subject():
                # It is the Root certificate
                break
            else:
                issuer_cert = self._get_issuer_cert(issuer_cert)
                self.chain_store.add_cert(issuer_cert)
                depth += 1
        try:
            store_ctx.verify_certificate()
        except Exception as e:
            raise exception.VerifyCertificateError(
                subject=issuer_cert.get_subject(),
                reason=e)

    def _check_crl(self):
        # NOTE(aloga): check CRLs for the last chain component issuer, as this
        # should correspond to the CA.
        cert = self.chain[-1]
        # Get cert issuer hash in hex lowercase
        h = format(int(cert.get_issuer().hash()), "02x")

        crl = self._load_crl(h)
        # FIXME(aloga): move to helper function
        cert_serial = format(cert.get_serial_number(), '02x')
        # The CRL list may be empty
        crls = crl.get_revoked() or []
        for rvk in crls:
            # XXX is this really like this?
            if cert_serial == rvk.get_serial().lower():
                raise exception.CertificateRevoked()


class VOMSContext(object):
    """Context Manager for VOMS handling."""

    def __init__(self,
                 vomsdir_path='/etc/grid-security/vomsdir',
                 ca_path='/etc/grid-security/certificates',
                 vomsapi_lib='libvomsapi.so.1'):

        self.vomsdir = vomsdir_path
        self.cadir = ca_path
        self.vomsapi = vomsapi_lib

    def _init_voms(self):
        # VOMS Stuff
        self.ffi = cffi.FFI()

        self.lib = self.ffi.dlopen(self.vomsapi)

        self.ffi.cdef('''
        struct voms {
            int siglen;
            char *signature;
            char *user;
            char *userca;
            char *server;
            char *serverca;
            char *voname;
            char *uri;
            char *date1;
            char *date2;
            int   type;
            struct data **std;
            char *custom;
            int datalen;
            int version;
            char **fqan;
            char *serial;
            /* changed these to void * */
            void *ac;
            void *holder;
        };
        struct vomsdata {
            char *cdir;
            char *vdir;
            struct voms **data;
            char *workvo;
            char *extra_data;
            int volen;
            int extralen;
            struct vomsdata *real;
        };
        extern struct vomsdata *VOMS_Init(char *voms, char *cert);
        extern void VOMS_Destroy(struct vomsdata *vd);
        extern int VOMS_SetVerificationType(int type,
                                            struct vomsdata *vd, int *error);
        /* use here void * for cert and chains */
        extern int VOMS_Retrieve(void *cert, void *chain, int how,
                                struct vomsdata *vd, int *error);
        ''')

        self.vd = self.lib.VOMS_Init(self.vomsdir, self.cadir)

    def __enter__(self):
        self._init_voms()
        return self

    def retrieve(self, cert, chain):
        # the chain is only available after verification, but pyopenssl
        # destroys objects release every time this is called, so manually
        # enforcing the call of verify + get_chain, then it must be
        # destroyed below
        store_ctx = crypto.X509StoreContext(chain, cert)
        _lib.X509_verify_cert(store_ctx._store_ctx)
        xch = _lib.X509_STORE_CTX_get_chain(store_ctx._store_ctx)
        error = self.ffi.new("int *")

        # FIXME(check error)
        res = self.lib.VOMS_Retrieve(cert._x509, xch, 0, self.vd, error)
        if res == 0:
            raise exception.VomsError(error[0])

        store_ctx._cleanup()
        d = {}
        for attr in ('user', 'userca', 'server', 'serverca',
                     'voname', 'uri', 'serial',
                     ('not_before', 'date1'), ('not_after', 'date2')):
            if isinstance(attr, basestring):
                d[attr] = self.ffi.string(getattr(self.vd.data[0], attr))
            else:
                d[attr[0]] = self.ffi.string(getattr(self.vd.data[0], attr[1]))

        d['version'] = self.vd.data[0].version
        d["fqans"] = []

        # for loop fails with:
        # TypeError: cdata 'char * *' does not support iteration
        # for fqan in vd.data[0].fqan:
        i = 0
        while True:
            fqan = self.vd.data[0].fqan[i]
            if fqan == self.ffi.NULL:
                break
            d["fqans"].append(self.ffi.string(fqan))
            i += 1
        return d

    def __exit__(self, type, value, tb):
        self.lib.VOMS_Destroy(self.vd)
