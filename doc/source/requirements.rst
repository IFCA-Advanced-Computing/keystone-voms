Requirements
============

The Keystone VOMS authentication module requires some additional packages to be
installed. Moreover, it requires that you run Keystone as a WSGI proccess behind
an HTTP server (Apache will be used in this documentation, but any webserver
could make it).

Required packages
-----------------

EUgridPMA CA certificates
~~~~~~~~~~~~~~~~~~~~~~~~~

You must have `EUgridPMA <http://www.eugridpma.org/>`_ certificates installed
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


VOMS libraries
~~~~~~~~~~~~~~
You must install the VOMS libraries. Please install the ``libvomsapi1`` package in Debian/Ubuntu or
``voms`` package in RedHat/Fedora/ScientificLinux/etc.


Apache Installation and Configuration
-------------------------------------

You need keystone working under Apache WSGI with ``mod_ssl`` enabled. To do so,
install the packages, and enable the relevant modules::

    sudo aptitude install apache2 libapache2-mod-wsgi
    sudo a2enmod ssl

Then configure your Apache server like this (we assume that you have the CA
certificates installed in the default location, otherwise you should adapt it to
your needs). Either enable the ``default-ssl`` site (``a2ensite default-ssl``) and
modify its configuration file (normally in ``/etc/apache2/sites-enabled/default-ssl``)
or create a new configuration file for your keystone installation
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

You should adjust the ``keystone.py`` file so that the configuration file
points to your keystone configuration file if it is not in the default location
(``/etc/keystone/keystone.conf``).

Also, do not forget to set the variable ``OPENSSL_ALLOW_PROXY_CERTS`` to
``1`` in your Apache environment (``/etc/apache2/envvars`` in Debian/Ubuntu) so
that X.509 proxy certificates are accepted by OpenSSL.

With the above configuration, and assuming that the Keystone host is
``keystone.example.org`` the endpoints will be as follow:

* ``https://keystone.example.org:5000/`` will be public and private endpoints,
  thus the Keystone URL will be ``https://keystone.example.org:5000/v2.0``
* ``https://keystone.example.org:35357/`` will be administration endpoint,
  thus the Keystone URL will be ``https://keystone.example.org:35357/v2.0``

SQL Token driver
~~~~~~~~~~~~~~~~

Since you are running Keystone as a WSGI service, you have to ensure that you
are using the SQL backend for the token storage, so as to make it possible to
share them between the diferent WSGI processes. Check that the keystone conf
file ``/etc/keystone/keystone.conf`` contains a ``[token]`` section as
follows::

  [token]
  driver = keystone.token.backends.sql.Token

Catalog
~~~~~~~

Your have to adjust your keystone catalog so that the identity backend points
to to the correct URLS as explained above. With the above configuration, these
URLs will be:

* public URL: ``https://keystone.example.org:5000/v2.0``
* admin URL: ``https://keystone.example.org:35357/v2.0``
* internal URL: ``https://keystone.example.org:5000/v2.0``

If you are using the SQL backend for storing your catalog, you should adjust it
manually to reflect the new endpoints.

PKI Tokens
~~~~~~~~~~

In order for the PKI tokens to work, you have to ensure that the keystone
WSGI processes, that will run as the user ``keystone`` in the example above,
have access to the configuration files. If you get this error::

    [error] ERROR:root:Command 'openssl' returned non-zero exit status 3
    [error] Traceback (most recent call last):
    [error]   File "/usr/lib/python2.7/dist-packages/keystone/common/wsgi.py", line 229, in __call__
    [error]     result = method(context, **params)
    [error]   File "/usr/lib/python2.7/dist-packages/keystone/token/controllers.py", line 151, in authenticate
    [error]     CONF.signing.keyfile)
    [error]   File "/usr/lib/python2.7/dist-packages/keystone/common/cms.py", line 140, in cms_sign_token
    [error]     output = cms_sign_text(text, signing_cert_file_name, signing_key_file_name)
    [error]   File "/usr/lib/python2.7/dist-packages/keystone/common/cms.py", line 135, in cms_sign_text
    [error]     raise subprocess.CalledProcessError(retcode, "openssl")
    [error] CalledProcessError: Command 'openssl' returned non-zero exit status 3

This may be that your keystone process cannot access the following file: 
``/etc/keystone/ssl/private/signing_key.pem`` so please ensure that the keystone
user can access that file.
