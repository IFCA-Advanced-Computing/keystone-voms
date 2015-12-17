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

You can install Keystone VOMS from any of the following repositories. If you
plan to install it like this, remove any prior version installed via pip.  And
check that you are removing the old versions. If you did not install this
module using pip, just ignore this step::

    # pip uninstall python-keystone-voms keystone-voms


Ubuntu 14.04
^^^^^^^^^^^^

First of all, install the repository key into the APT list of trusted keys::

    # curl http://download.opensuse.org/repositories/home:/aloga:/cloud-integration:/liberty/xUbuntu_14.04/Release.key | apt-key add -

Make sure that you don't have any other cloud integration repo for an old
release, and add the repository to your ``sources.list.d`` directory::

    # echo "deb http://download.opensuse.org/repositories/home:/aloga:/cloud-integration:/liberty/xUbuntu_14.04/ ./" \
      | tee /etc/apt/sources.list.d/aloga-cloud-integration-liberty.list
    # apt-get update
    # apt-get install python-keystone-voms


Install from pip
~~~~~~~~~~~~~~~~

Before the PyPi package was called ``python-keystone-voms``. You should remove
if before installing it::

    # pip uninstall python-keystone-voms

With a running Keystone Icehouse you can install the VOMS module with the
following command (note the version range)::

    # pip install 'keystone-voms>=8.0.0,<9.0.0'

Install from source
~~~~~~~~~~~~~~~~~~~

First, uninstall any old ``python-keystone-voms`` installation. This was the
old name of the package and should be removed::

    # pip uninstall python-keystone-voms

With a running Keystone Icehouse, simply install this egg. In the upper-level
directory run ``python setup.py install``::

    # git clone git://github.com/IFCA/keystone-voms.git -b stable/liberty
    # cd keystone-voms
    # pip install .

Enable the Keystone VOMS module
-------------------------------

The authentication module is a WSGI middleware that performs the authentication
and passes the authenticated user down to keystone. Add the VOMS filter to your
paste configuration file ``/etc/keystone/keystone-paste.ini`` (note that in
Icehouse paste configuration has been moved to a separate configuration file
and it is not anymore in the same file as the Keystone configuration). First,
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
