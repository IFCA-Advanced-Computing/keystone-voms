VOMS module Installation
========================

This module assumes that keystone is at least running the Icehouse.
If you are using the Grizzly version, please check the `Grizzly Documentation
<http://keystone-voms.readthedocs.org/en/stable-grizzly/>`_.

Install the Keystone VOMS module
--------------------------------

Install from PPA
~~~~~~~~~~~~~~~~

This option is no longer supported. Please install it from the source as stated
below.

Install from pip
~~~~~~~~~~~~~~~~

With a running Keystone Icehouse you can install the VOMS module with the
following command (note the version range)::

    pip install 'python-keystone-voms>=2014.1,<2014.2'

Install from source
~~~~~~~~~~~~~~~~~~~

First, uninstall any other `keystone-voms` installation::

    sudo pip uninstall keystone-voms

With a running Keystone Icehouse, simply install this egg. In the upper-level
directory run ``python setup.py install``::

    git clone git://github.com/IFCA/keystone-voms.git -b stable/icehouse
    cd keystone-voms
    sudo pip install .

Enable the Keystone VOMS module
-------------------------------

The authentication module is a WSGI middleware that performs the authentication
and passes the authenticated user down to keystone. Add the VOMS filter to your
paste configuration file ``/etc/keystone/keystone-paste.ini`` (note that in
Icehouse paste configuration has been moved to a separate configuration file
and it is not anymore in the same file as the Keystone configuration). First,
add the VOMS filter as follows::

    [filter:voms]
    paste.filter_factory = keystone_voms:VomsAuthNMiddleware.factory

Then add this filter to the ``public_api`` pipeline for the version V2 of your
API. Probably, you should add it before the ``debug``, ``ec2_extension``,
``user_crud_extension`` and ``public_service`` components::

    [pipeline:public_api]
    pipeline = access_log sizelimit url_normalize token_auth admin_token_auth xml_body json_body voms debug ec2_extension user_crud_extension public_service


Note that you may have a different pipeline. You don't need to replace your
pipeline with the above, but just add the ``voms`` filter in the corrin the
correct place.
