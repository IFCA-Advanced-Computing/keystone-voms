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

VOMS Overview
=============

The VOMS service can issue x509 proxies based on RFC 3820
(https://www.ietf.org/rfc/rfc3820.txt) by using the ``-rfc`` option in
the comandline. Instead of using plain X.509 certificates this proxy can
be used to authenticate against a properly configured Keystone server.

Keystone VOMS Overview
======================

Follow this guide to enable your Keystone to be used with VOMS authentication.
No modifications in the DB are needed, since it
will be installed as an external plugin. Therefore, your Keystone will be usable
with any other authentication mechanism that you had implemented (such as the
native Keystone authentication).

This VOMS authentication module assumes that Keystone is working behind
an http server as a WSGI application. SSL must be enabled in the http server.

Currently it only works with the V2 API of Keystone, a module compatible
with the V3 API a work in progress.

How does it work?
=================

SSL info is obtained from the request environment. The authentication module
uses the VOMS library to check if the VOMS proxy is valid and if it is allowed
in this server. The mapping between a VO, VO group and a keystone tenant is
made in a configurable JSON file. For the moment there is no mapping for the
Roles and/or Capabilities incoming from the VOMS credentials.

The mapped local tenant must exist in advance for a user to be authenticated.
If the mapped tenant doest not exist, the authentication will fail. The same
applies for the user, with the particularity that the backend is able to
autocreate new incoming users if the ``autocreate_users`` is enabled in the
configuration file and the authentication is sucessful (i.e. the proxy is
accepted and it is valid). This option is disabled by default, but if you want
to let all the users from a VO to get into your infrastructure you should consider
enabling it. Once a user has been granted access, you can manage it as you will
do with any other user in keystone (e.g. disable/enable, grant/revoke roles,
etc.).

In order to get an unscoped token, you must POST to ``/tokens``, with the
following JSON document document in the request::

    {
        "auth": {
            "voms": "true"
        }
    }

This request should return you your an unscoped token. Next step is the
discovery of your tenant (that may differ from the VO name). You have to use a
GET request to ``/tenants`` passing the ID of your unscoped token (that you
obtained before) in the ``X-Auth-Token`` header.

For further details, check the :doc:`test` section.
