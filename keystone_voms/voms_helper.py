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

import ctypes


class _voms(ctypes.Structure):
    _fields_ = [
        ("siglen", ctypes.c_int32),
        ("signature", ctypes.c_char_p),
        ("user", ctypes.c_char_p),
        ("userca", ctypes.c_char_p),
        ("server", ctypes.c_char_p),
        ("serverca", ctypes.c_char_p),
        ("voname", ctypes.c_char_p),
        ("uri", ctypes.c_char_p),
        ("date1", ctypes.c_char_p),
        ("date2", ctypes.c_char_p),
        ("type", ctypes.c_int32),
        ("std", ctypes.c_void_p),
        ("custom", ctypes.c_char_p),
        ("datalen", ctypes.c_int32),
        ("version", ctypes.c_int32),
        ("fqan", ctypes.POINTER(ctypes.c_char_p)),
        ("serial", ctypes.c_char_p),
        ("ac", ctypes.c_void_p),
        ("holder", ctypes.c_void_p),
    ]


class _vomsdata(ctypes.Structure):
    _fields_ = [
        ("cdir", ctypes.c_char_p),
        ("vdir", ctypes.c_char_p),
        ("data", ctypes.POINTER(ctypes.POINTER(_voms))),
        ("workvo", ctypes.c_char_p),
        ("extra_data", ctypes.c_char_p),
        ("volen", ctypes.c_int32),
        ("extralen", ctypes.c_int32),
        ("real", ctypes.c_void_p),
    ]


class VOMS(object):
    """Context Manager for VOMS handling"""

    def __init__(self, vomsdir_path, ca_path, vomsapi_lib):
        self.VOMSApi = ctypes.CDLL(vomsapi_lib)
        self.VOMSApi.VOMS_Init.restype = ctypes.POINTER(_vomsdata)

        self.VOMSDIR = vomsdir_path
        self.CADIR = ca_path

        self.vd = None

    def __enter__(self):
        self.vd = self.VOMSApi.VOMS_Init(self.VOMSDIR, self.CADIR).contents
        return self

    def set_no_verify(self):
        """Skip verification of AC.

        This method skips the AC signature verification, this it should
        only be used for debugging and tests.
        """

        error = ctypes.c_int32(0)
        self.VOMSApi.VOMS_SetVerificationType(0x040,
                                              ctypes.byref(self.vd),
                                              ctypes.byref(error))

    def retrieve(self, cert, chain):
        """Retrieve VOMS credentials from a certificate and chain."""

        self.error = ctypes.c_int32(0)

        cert_ptr = ctypes.cast(long(cert._ptr()), ctypes.c_void_p)
        chain_ptr = ctypes.cast(long(chain._ptr()), ctypes.c_void_p)

        res = self.VOMSApi.VOMS_Retrieve(cert_ptr,
                                         chain_ptr,
                                         0,
                                         ctypes.byref(self.vd),
                                         ctypes.byref(self.error))
        if res == 0:
            return None
        else:
            return self.vd.data.contents.contents

    def __exit__(self, type, value, tb):
        self.VOMSApi.VOMS_Destroy(ctypes.byref(self.vd))
