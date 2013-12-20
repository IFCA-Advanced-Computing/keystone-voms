VOMS module Installation
========================

This module assumes that keystone is at least running the Havana version.
If you are using the Grizzly version, please check the `Grizzly Documentation
<http://keystone-voms.readthedocs.org/en/stable-grizzly/>`_.

Install the Keystone VOMS module
--------------------------------

Install from the Python Package Index
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

You can install it directly from PyPI::

    pip install keystone_voms

Install from PPA
~~~~~~~~~~~~~~~~

You can install the latest version from a private PPA::

   sudo add-apt-repository ppa:aloga/keystone-voms
   sudo aptitude update
   sudo aptitude install python-keystone-voms

Install from source
~~~~~~~~~~~~~~~~~~~

With a running Havana installation, simply install this egg. In the upper-level
directory run ``python setup.py install``::

    git clone git://github.com/IFCA/keystone-voms.git -b stable/havana
    cd keystone-voms
    sudo python setup.py install

Enable the Keystone VOMS module
-------------------------------

The authentication module is a WSGI middleware that performs the authentication
and passes the authenticated user down to keystone. Add the VOMS filter to your
paste configuration file ``/etc/keystone/keystone-paste.ini`` (note that in
Havana the paste configuration has been moved to a separate configuration file
and it is not anymore in the same file as the Keystone configuration). First,
add the VOMS filter as follows::

    [filter:voms]
    paste.filter_factory = keystone_voms:VomsAuthNMiddleware.factory

Then add this filter to the ``public_api`` pipeline for the version V2 of your
API. Probably, you should add it before the ``debug``, ``ec2_extension``,
``user_crud_extension`` and ``public_service`` components::

    [pipeline:public_api]
    pipeline = access_log sizelimit url_normalize token_auth admin_token_auth xml_body json_body ldap_ro_ifca ldap_ro_lip voms debug ec2_extension user_crud_extension public_service


Note that you may have a different pipeline. You don't need to replace your
pipeline with the above, but just add the ``voms`` filter in the corrin the
correct place.
