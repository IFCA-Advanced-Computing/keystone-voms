Keystone VOMS Overview
======================

This VOMS authentication module assumes that Keystone is working behind
an httpd server as a WSGI service with OpenSSL enabled. It only works with the
V2 API of Keystone, since the V3 is still a work in progress.

This module asumes that Keystone has support for external authentication
as implemented in the `Pluggable Identity Authentication Handlers Blueprint`_. 

.. _Pluggable Identity Authentication Handlers Blueprint: https://blueprints.launchpad.net/keystone/+spec/pluggable-identity-authentication-handlers

SSL info is obtained from the request environment. The authentication module
uses the voms library to check if the VOMS proxy is valid and if it is allowed
in this server. The mapping between a VO, VO group and a keystone tenant is
made in a configurable JSON file.

The mapped local tenant must exist in advance for a user to be authenticated.
If the mapped tenant doest not exist, the authentication will fail. The same
applies for the user, with the particularity that the backend is able to
autocreate new users if the ``autocreate_users`` is enabled in the
configuration file. This option is disabled by default, but if you want to
let all the users from a VO to get into your infrastructre you should consider
enabling it. Once a user has been granted access, you can manage it as you will
do with any other user in keystone (i.e. disable/enable, grant/revoke roles,
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

For further details, check the :ref:`test` section.
