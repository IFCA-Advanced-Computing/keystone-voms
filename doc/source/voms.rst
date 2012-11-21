===================================
Keystone VOMS Authentication Module
===================================

VOMS Introduction
=================

The VOMS service can issue x509 proxies based on RFC 3820
(https://www.ietf.org/rfc/rfc3820.txt) by using the ``-rfc`` option in
the comandline. Instead of using plain x509 certificates this proxy can
be used to authenticate against a properly configured Keystone server.

VOMS Authentication Module
==========================

This VOMS authentication module assumes that Keystone is working behind
an httpd server as a WSGI service with OpenSSL enabled. Please note that
for OpenSSL to verify proxy certificates the environment variable
``OPENSSL_ALLOW_PROXY_CERTS`` must be set to anything but 0 (add it to
``/etc/apache2/envvars`` in Ubuntu).

This module asumes that Keystone has support for external authentication
as per the `Pluggable Identity Authentication Handlers Blueprint`_. 

.. _Pluggable Identity Authentication Handlers Blueprint: https://blueprints.launchpad.net/keystone/+spec/pluggable-identity-authentication-handlers

SSL info is fetched from the request environment. The authentication module
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

In order to authenticate, you must post a JSON request in the body containing
the following::

    {
        "auth": {
            "voms": "true"
        }
    }

Note that no ``tenantName`` should be requested at all, since this will be
extracted from the VOMS AC.

Installation
============

Normal installation
-------------------

This module relies on the `Pluggable Identity Authentication Handlers
Blueprint`_ that has been implemented in commit `f79f701`_. This means that
you need to have a keystone version in the Grizzly series to get the module
working.

.. _f79f701: https://github.com/openstack/keystone/commit/f79f701782fa583380138e1fba702fb00bcac52e

Once you have a Grizzly keystone installation, you have to drop the
`keystone/middleware/voms_authn/`_  directory inside the middleware
directory of your installation (normally it should be under 
`/usr/lib/python2.7/dist-packages/keystone/middleware/`) and configure it.

.. _keystone/middleware/voms_authn/: https://github.com/alvarolopez/keystone/tree/voms/authn_as_middleware/keystone/middleware/voms_authn

An alternative is to directly install the packages from ... that contain 
the code ready for use. However, these packages might not be updated to
the latest version.

Devstack installation
---------------------

You can deploy it using devstack (http://devstack.org/). Use the following
``localrc`` just to install keystone and test it::

    ENABLED_SERVICES=key,mysql
    KEYSTONE_REPO=git://github.com/alvarolopez/keystone.git

Since keystone will be executed as an WSGI application on Apache, you have to
stop the the running devstack instance, so after running ``stack.sh`` you 
should run ``unstack.sh`` to stop it.

Configuration
=============

Apache Configuration
--------------------

First of all you need keystone working under Apache WSGI with ``mod_ssl``
enabled. To do so, install the packages, and enable the relevant modules::

    sudo aptitude install apache2 libapache2-mod-wsgi
    sudo a2enmod ssl

Then configure your Apache server like this (adapt it to your needs). Either
enable the ``default-ssl`` site (``a2ensite default-ssl``) and modify its
configuration file (normally in ``/etc/apache2/sites-enabled/default-ssl``) or
create a new configuration file for your keystone installation
``/etc/apache2/sites-enabled/keystone``::

    WSGIDaemonProcess keystone user=keystone group=nogroup processes=3 threads=10

    Listen 5000
    <VirtualHost _default_:5000>
        LogLevel warn
        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/ssl_access.log combined

        SSLEngine on
        SSLCertificateFile    /etc/ssl/certs/ssl.cert
        SSLCertificateKeyFile /etc/ssl/private/ssl.key


        SSLCACertificatePath /etc/grid-security/certificates
        SSLCARevocationPath /etc/grid-security/certificates
        SSLVerifyClient optional
        SSLVerifyDepth 10
        SSLProtocol all -SSLv2
        SSLCipherSuite ALL:!ADH:!EXPORT:!SSLv2:RC4+RSA:+HIGH:+MEDIUM:+LOW
        SSLOptions +StdEnvVars +ExportCertData

        WSGIScriptAlias /  /usr/lib/cgi-bin/keystone/main
        WSGIProcessGroup keystone
    </VirtualHost>

    Listen 35357
    <VirtualHost _default_:35357>
        LogLevel warn
        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/ssl_access.log combined
    
        SSLEngine on
        SSLCertificateFile    /etc/ssl/certs/hostcert.pem
        SSLCertificateKeyFile /etc/ssl/private/hostkey.pem
    
    
        SSLCACertificatePath /etc/grid-security/certificates
        SSLCARevocationPath /etc/grid-security/certificates
        SSLVerifyClient optional
        SSLVerifyDepth 10
        SSLProtocol all -SSLv2
        SSLCipherSuite ALL:!ADH:!EXPORT:!SSLv2:RC4+RSA:+HIGH:+MEDIUM:+LOW
        SSLOptions +StdEnvVars +ExportCertData
    
        WSGIScriptAlias / /usr/lib/cgi-bin/keystone/admin
        WSGIProcessGroup keystone
    </VirtualHost>


To run keystone as a WSGI app, copy ``httpd/keystone.py`` to
``/usr/lib/cgi-bin/keystone/keystone.py`` and create the following links::

    sudo mkdir -p /usr/lib/cgi-bin/keystone
    sudo cp httpd/keystone.py /usr/lib/cgi-bin/keystone/keystone.py
    sudo ln /usr/lib/cgi-bin/keystone/keystone.py /usr/lib/cgi-bin/keystone/main
    sudo ln /usr/lib/cgi-bin/keystone/keystone.py /usr/lib/cgi-bin/keystone/admin
    sudo service apache2 restart

You should ajust the ``keystone.py`` file so that the configuration file
points to your keystone configuration file.

Also, do not forget to set the variable ``OPENSSL_ALLOW_PROXY_CERTS`` to
anything but 0 in your Apache environment (``/etc/apache2/envvars`` in
Debian/Ubuntu).

EUGridPMA CAs
-------------

You must have `EUgridPMA <http://www.eugridpma.org/>` certificates installed
on its standard location (``/etc/grid-security/certificates``) and the 
``fetch-crl`` package properly working so as have the CRLs up to date::

    wget -q -O - https://dist.eugridpma.info/distribution/igtf/current/GPG-KEY-EUGridPMA-RPM-3 | apt-key add - 
    echo "deb http://repository.egi.eu/sw/production/cas/1/current egi-igtf core" > /etc/apt/sources.list.d/egi-cas.list
    sudo aptitude update
    sudo aptitude install ca-policy-egi-core

Grab and install the ``fetch-crl`` package. Version 3 does not work properly,
so get version 2.8.5 instead::

    wget http://ftp.de.debian.org/debian/pool/main/f/fetch-crl/fetch-crl_2.8.5-2_all.deb
    sudo dpkg -i fetch-crl_2.8.5-2_all.deb
    sudo fetch-crl

Allowed VOs
-----------

Add the ``.lsc`` files to ``/etc/grid-security/vomsdir/``. For each VO you need
a subdirectory in that directory, containing as much LSC files as VOMS servers
are trusted for that VO. The LSC file must contain:

* First line: subject DN of the VOMS server host certificate.
* Second line: subject DN of the CA that issued the VOMS server host certificate.

So, for example, for the `dteam VO <http://operations-portal.egi.eu/vo/view/voname/dteam>`
this file should be::

    $ cat /etc/grid-security/vomsdir/dteam/voms.hellasgrid.gr.lsc
    /C=GR/O=HellasGrid/OU=hellasgrid.gr/CN=voms.hellasgrid.gr
    /C=GR/O=HellasGrid/OU=Certification Authorities/CN=HellasGrid CA 2006

The dteam VO has two VOMS servers (see link above) so another file for the
second server needs to be present::

    $ cat /etc/grid-security/vomsdir/dteam/voms2.hellasgrid.gr.lsc
    /C=GR/O=HellasGrid/OU=hellasgrid.gr/CN=voms2.hellasgrid.gr
    /C=GR/O=HellasGrid/OU=Certification Authorities/CN=HellasGrid CA 2006


Additional packages
-----------------

Apart from keystone, Apache, the EUGridPMA distribution and ``fetch-crl``
package, you need the VOMS api (``libvomsapi1`` package in ubuntu, ``voms``
package in RH/Fedora).

Keystone configuration
----------------------

Authentication module
~~~~~~~~~~~~~~~~~~~~~

The authentication module is a WSGI middleware that performs the authentication
and passes the authenticated user down to keystone. In order to use it, you must
have a middlware filter declared and added to the keystone pipeline (after the
``json_body`` filter). Check that your ``/etc/keystone/keystone.conf`` looks
like::

    [filter:vomsauthn]
    paste.filter_factory = keystone.middleware.voms_authn:VomsAuthNMiddleware.factory

    [pipeline:public_api]
    pipeline = stats_monitoring url_normalize token_auth admin_token_auth xml_body json_body vomsauthn debug ec2_extension user_crud_extension public_service

voms options
~~~~~~~~~~~~

There are several new options in ``/etc/keystone/keystone.conf`` that are used
to configure the VOMS identity behaviour. The default values should be OK for
most installations. These are under the ``[voms]`` section::

    [voms]
    vomsdir_path = /etc/grid-security/vomsdir
    ca_path = /etc/grid-security/certificates
    voms_policy = /etc/keystone/voms.json
    vomsapi_lib = libvomsapi.so.1
    autocreate_users = False

* ``vomsdir_path``: Path storing the ``.lsc`` files.
* ``ca_path``: Path where the CAs and CRLs are stored.
* ``voms_policy``: JSON file containing the VO/tenant/role mapping.
* ``vomsapi_lib``: Path to the voms library to use.
* ``vomsapi_lib``: Whether a user should be autocreated if it does not exist.
* ``autocreate_users``: Whether we must create the users for the trusted VOs on the fly.

Token driver
~~~~~~~~~~~~

You have to use the SQL backend for the tokens, so as to make it possible to
share them between the diferent WSGI processes. Edit the keystone configuration
file ``/etc/keystone/keystone.conf`` and modify the ``[token]`` section as
follows::

  [token]
  driver = keystone.token.backends.sql.Token

voms.json
~~~~~~~~~

The VO and VO group mapping to the local tenants is made in the JSON
file ``/etc/keystone/voms.json``. It is based on the VO name and VOMS
proxy fqan::

  {
      "voname": {
          "tenant": "local_tenant"
      }
  }

For example for the dteam VO, it could be configured as::

  {
      "dteam": {
          "tenant": "dteam"
      },
      "/dteam/NGI_IBERGRID": {
          "tenant": "dteam_ibergrid"
      }
  }

Catalog
~~~~~~~

Your have to adjust your keystone catalog so that the identity backend points
to to the correct url. Assuming that you are using template catalog, edit the
``/etc/keystone/default_catalog.templates``::

  catalog.RegionOne.identity.publicURL = https://<your_ks_host>/main/v2.0
  catalog.RegionOne.identity.adminURL = https://<your_ks_host>/admin/v2.0
  catalog.RegionOne.identity.internalURL = https://<your_ks_host>/main/v2.0
  catalog.RegionOne.identity.name = Identity Service

If you are using any other backend, you should adjust it manually.

Test it!
========

Once you have everything configured you can test it requesting a token using
a valid VOMS proxy::

  $ voms-proxy-init -voms <VOMS> -rfc
  $ curl --insecure --cert $X509_USER_PROXY  -d \
   '{"auth":{"voms": "true"}}' -H "Content-type: \
    application/json" https://<keystone_host>/main/v2.0/tokens

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

You have to check double check that the ``vomsdir_path`` and ``ca_path``
configuration options (that default to ``/etc/grid-security/vomsdir`` and
``/etc/grid-security/certificates`` respectively) point to the correct path.
Also ensure that the ``.lsc`` files have the right contents. and that the CLRs
are up to date.
