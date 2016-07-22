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

VOMS module Installation
========================

This module assumes that you are running the Keystone 8 (Liberty) version.

Install the Keystone VOMS module
--------------------------------

Install from Repositories
~~~~~~~~~~~~~~~~~~~~~~~~~

You can install Keystone VOMS from any of the repositories published in the
AppDB. If you plan to install it like this, remove any prior version installed
via pip and check that you are removing the old versions. If you did not
install this module using pip, just ignore this step::

    # pip uninstall python-keystone-voms keystone-voms

Please, do not use the OpenSuse build service anymore and switch to the EGI
AppDB repositories. Please visit the `Keystone-VOMS product page
<https://appdb.egi.eu/store/software/keystone.voms>`_ where you can find the
download page for all the available and supported versions.

Install from pip
~~~~~~~~~~~~~~~~

With a running Keystone you can install the VOMS module with the
following command (note the version range)::

    # pip install 'keystone-voms>=8.0.0,<9.0.0'

Install from source
~~~~~~~~~~~~~~~~~~~

First, uninstall any old ``python-keystone-voms`` installation. This was the
old name of the package and should be removed::

    # pip uninstall python-keystone-voms

With a running Keystone, simply install this egg. In the upper-level
directory run ``python setup.py install``::

    # git clone git://github.com/IFCA/keystone-voms.git -b stable/liberty
    # cd keystone-voms
    # pip install .

Enable the Keystone VOMS module
-------------------------------

The authentication module is a WSGI middleware that performs the authentication
and passes the authenticated user down to keystone. Add the VOMS filter to your
paste configuration file (``/etc/keystone/keystone-paste.ini`` is the default one
in Ubuntu, ``/usr/share/keystone/keystone-dist-paste.ini`` in CentOS). First,
add the VOMS filter as follows::

    [filter:voms]
    paste.filter_factory = keystone_voms.core:VomsAuthNMiddleware.factory

Then add this filter to the ``public_api`` pipeline for the version V2 of your
API. Probably, you should add it before the ``debug``, ``ec2_extension``,
``user_crud_extension`` and ``public_service`` components::

    [pipeline:public_api]
    (...)
    pipeline = sizelimit url_normalize build_auth_context token_auth admin_token_auth xml_body_v2 json_body ec2_extension voms user_crud_extension public_service

Note that you may have a different pipeline. You don't need to replace your
pipeline with the above, but just add the ``voms`` filter in the correct place.
