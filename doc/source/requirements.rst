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

Requirements
============

The Keystone VOMS authentication module requires some additional packages to be
installed. Moreover, it requires that you run Keystone as a WSGI application behind
an HTTP server (Apache will be used in this documentation, but any webserver
could make it). Keystone project has deprecated eventlet, so you should be already
running Keystone in such way.

* Keystone Mitaka.
* EUgridPMA CA certificates at the latest version.
* fetch-crl package.
* VOMS libraries.
* HTTP server with WSGI enabled.

EUgridPMA CA certificates and fetch-crl
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

You must have `EUgridPMA <http://www.eugridpma.org/>`_ certificates installed
on its standard location (``/etc/grid-security/certificates``) and the
``fetch-crl`` package properly working so as have the CRLs up to date.

Ubuntu 14.04
^^^^^^^^^^^^

Use these commands to install on Ubuntu::

    $ wget -q -O - https://dist.eugridpma.info/distribution/igtf/current/GPG-KEY-EUGridPMA-RPM-3 | apt-key add -
    $ echo "deb http://repository.egi.eu/sw/production/cas/1/current egi-igtf core" \
      | tee --append /etc/apt/sources.list.d/egi-cas.list
    $ apt-get update
    $ apt-get install ca-policy-egi-core fetch-crl
    $ fetch-crl

CentOS 7
^^^^^^^^

Install CAs and fetch-crl with::

    $ curl -L http://repository.egi.eu/sw/production/cas/1/current/repo-files/EGI-trustanchors.repo | sudo tee /etc/yum.repos.d/EGI-trustanchors.repo
    $ sudo yum install ca-policy-egi-core fetch-crl

VOMS libraries
~~~~~~~~~~~~~~

You must install the VOMS libraries. Please install the ``libvomsapi1`` package in Debian/Ubuntu or
``voms`` package in RedHat/Fedora/ScientificLinux/etc::

    $ apt-get install libvomsapi1

Apache Installation and Configuration
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. note::
    Since Kilo, the keystone project deprecates Eventlet in favor of a WSGI
    server. This guide assumes that you already have a Keystone instance using
    the Apache HTTP server with mod_wsgi to serve Keystone requests on ports
    5000 and 35357.

You need Keystone working under Apache WSGI with ``mod_ssl`` enabled. The
standard installation starting on Liberty, guides through this setup, so during
thise guide we will only set up the SSL part. To do so, enable the relevant
module.

Ubuntu::

    $ a2enmod ssl

CentOS::

    $ yum install mod_ssl

Then add to your Apache Keystone WSGI configuration the SSL options as shown below.
We assume that you have the CA certificates installed in the default location,
otherwise you should adapt it to your needs, also check that the paths of the wsgi
script are correct for your installation. The location of the configuration file
for the keystone service under Apache depends on your distribution (e.g. in Ubuntu is
``/etc/apache2/sites-available/wsgi-keystone.conf``, in CentOS 7 is
``/etc/httpd/conf.d/wsgi-keystone.conf``). Note that you need a valid certificate
for the http server (``SSLCertificateFile`` and ``SSLCertificateKeyFile``)::

    Listen 5000
    WSGIDaemonProcess keystone user=keystone group=nogroup processes=8 threads=1
    <VirtualHost _default_:5000>
        LogLevel     warn
        ErrorLog    ${APACHE_LOG_DIR}/error.log
        CustomLog   ${APACHE_LOG_DIR}/ssl_access.log combined

        SSLEngine               on
        SSLCertificateFile      /etc/ssl/certs/hostcert.pem
        SSLCertificateKeyFile   /etc/ssl/private/hostkey.pem
        SSLCACertificatePath    /etc/grid-security/certificates
        SSLCARevocationPath     /etc/grid-security/certificates
        SSLVerifyClient         optional
        SSLVerifyDepth          10
        SSLProtocol             all -SSLv2
        SSLCipherSuite          ALL:!ADH:!EXPORT:!SSLv2:RC4+RSA:+HIGH:+MEDIUM:+LOW
        SSLOptions              +StdEnvVars +ExportCertData

        WSGIScriptAlias /  /var/www/cgi-bin/keystone/main
        WSGIProcessGroup keystone
    </VirtualHost>

    Listen 35357
    WSGIDaemonProcess   keystoneapi user=keystone group=nogroup processes=8 threads=1
    <VirtualHost _default_:35357>
        LogLevel    warn
        ErrorLog    ${APACHE_LOG_DIR}/error.log
        CustomLog   ${APACHE_LOG_DIR}/ssl_access.log combined

        SSLEngine               on
        SSLCertificateFile      /etc/ssl/certs/hostcert.pem
        SSLCertificateKeyFile   /etc/ssl/private/hostkey.pem
        SSLCACertificatePath    /etc/grid-security/certificates
        SSLCARevocationPath     /etc/grid-security/certificates
        SSLVerifyClient         optional
        SSLVerifyDepth          10
        SSLProtocol             all -SSLv2
        SSLCipherSuite          ALL:!ADH:!EXPORT:!SSLv2:RC4+RSA:+HIGH:+MEDIUM:+LOW
        SSLOptions              +StdEnvVars +ExportCertData

        WSGIScriptAlias     / /var/www/cgi-bin/keystone/admin
        WSGIProcessGroup    keystoneapi
    </VirtualHost>

As you can see, the ``SSLVerifyClient`` is set to ``optional``, so that people
without a VOMS proxy can authenticate using their Keystone credentials.

Next, set the variable ``OPENSSL_ALLOW_PROXY_CERTS`` to ``1`` in your Apache
environment configuration file (``/etc/apache2/envvars`` in Debian/Ubuntu,
``/etc/sysconfig/httpd`` in CentOS) so that X.509 proxy certificates are
accepted by OpenSSL. This is an important thing, so please double check that
you have really enabled it.

Ubuntu::

    $ echo "export OPENSSL_ALLOW_PROXY_CERTS=1" >> /etc/apache2/envvars

CentOS::

    $ echo "OPENSSL_ALLOW_PROXY_CERTS=1" >> /etc/sysconfig/httpd


With the above configuration, and assuming that the Keystone host is
``keystone.example.org`` the endpoints will be as follow:

* ``https://keystone.example.org:5000/`` will be public and private endpoints,
  thus the Keystone URL will be ``https://keystone.example.org:5000/v2.0``
* ``https://keystone.example.org:35357/`` will be administration endpoint,
  thus the Keystone URL will be ``https://keystone.example.org:35357/v2.0``


Catalog
~~~~~~~

If you did not have Keystone running behind https your have to adjust your
Keystone catalog so that the identity backend points to to the correct URLS as
explained above. With the above configuration, these URLs will be:

* public URL: ``https://keystone.example.org:5000/v2.0``
* admin URL: ``https://keystone.example.org:35357/v2.0``
* internal URL: ``https://keystone.example.org:5000/v2.0``

Note that the rest of the OpenStack configuration should be adjusted.
