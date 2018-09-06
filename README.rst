Description
----------

This project includes a set of sample Python scripts and Ansible playbooks that utilize the Redfish API to manage Lenovo ThinkSystem servers.  The scripts use the DMTF python-redfish-library (https://github.com/DMTF/python-redfish-library).

For more information on the Redfish API, visit http://redfish.dmtf.org/

Installing
----------

* To install the python-redfish-library, get the code from https://github.com/DMTF/python-redfish-library , then:

.. code-block:: console

	python setup.py install

* To install Ansible:

.. code-block:: console

	sudo apt install ansible
	sudo yum install ansible


Requirements
----------
* python-redfish-library need to be installed

Usage
----------
A set of python examples is provided under the examples directory of this project. In addition to the examples, there are sample ansible playbook implementations that can be used as a reference to build on the python examples.


Using the python examples to get and set values
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Simply run the python script to print out the values form the HTTP GET operation.

This example prints the current system power state (such as On or Off)

.. code-block:: console

	cd examples
	python lenovo_get_power_state.py


This example prints the system reset types that are supported by this server, then passes one of the values (ForceOff) to force the server to shutdown:

.. code-block:: console
	cd examples
	python lenovo_get_reset_types.py
	['On', 'Nmi', 'GracefulShutdown', 'GracefulRestart', 'ForceOn', 'ForceOff', 'ForceRestart']

	Python lenovo_set_reset_types.py ForceOff



Using ansible playbooks to get and set values
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
A simple ansible playbook defined in the ansible_playbooks directory can be used as reference to create similar playbooks.

.. code-block:: yaml

    - hosts: 127.0.0.1
        tasks:
    - name: run scripts based on script_name
        command: python ../examples/{{script_name}}
        register: script_output
    - debug: var=script_output.stdout


Running ansible playbooks to get and set values
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Run the ansible playbooks from the ansible_playbooks directory. The way to run get_values and set_values playbooks is shown below:

.. code-block:: shell-session

    ansible-playbook lenovo_set_values.yml --extra-vars "script_name=<script_name>.py parameter=<parameter>"
    ansible-playbook lenovo_get_values.yml --extra-vars "script_name=<script_name>.py"



Contributing
----------

1. Fork it!
2. Create your feature branch: `git checkout -b my-new-feature`
3. Commit your changes: `git commit -am 'Add some feature'`
4. Push to the branch: `git push origin my-new-feature`
5. Submit a pull request :D

History
----------

* 10/12/2017 : Initial version

Copyright and License
---------------------

Copyright 2017 Lenovo Corporation

Licensed under the Apache License, Version 2.0 (the "License"); you may
not use this file except in compliance with the License. You may obtain
a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
License for the specific language governing permissions and limitations
under the License.

