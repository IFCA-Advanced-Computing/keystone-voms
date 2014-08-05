..
      Copyright 2012 Spanish National Research Council

      Licensed under the Apache License, Version 2.0 (the "License"); you may
      not use this file except in compliance with the License. You may obtain
      a copy of the License at

          http://www.apache.org/licenses/LICENSE-2.0

      Unless required by applicable law or agreed to in writing, software
      distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
      WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
      License for the specific language governing permissions and limitations
      under the License.

Troubleshooting
===============

Apache complains about issuer of certificate
--------------------------------------------

You get something like::

  Certificate Verification: Error (20): unable to get local issuer certificate

You probably missed to set the ``OPENSSL_ALLOW_PROXY_CERTS`` variable on the
Apache environment

Error 14: Signature error
-------------------------

You have to double check that the ``vomsdir_path`` and ``ca_path``
configuration options (that default to ``/etc/grid-security/vomsdir`` and
``/etc/grid-security/certificates`` respectively) point to the correct path.
Also ensure that the ``.lsc`` files have the right contents and that the CLRs
are up to date.
