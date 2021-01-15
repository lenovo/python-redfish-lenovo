# ansible-playbooks

Sample Ansible playbooks for using the Redfish API on Lenovo servers

Description
----------

This folder includes a set of sample Ansible playbooks that utilize the Redfish API to manage Lenovo ThinkSystem servers.  The playbooks use redfish_facts/redfish_command/redfish_config modules which are in Ansible or community.general collection since Ansible version 2.10

For more information on the Redfish API, visit <http://redfish.dmtf.org/>

For more information on the Ansible, visit <https://docs.ansible.com/ansible/latest/>

For more information on the community.general collection, visit <https://github.com/ansible-collections/community.general>

Installing
----------

* To install Ansible:
    
    `pip install ansible`

    Without version specified, newest version will be installed. If you want specific version, specify it as below:

    `pip install ansible==2.8`

* To install community.general collection (Needed since Ansible version 2.10):

    `ansible-galaxy collection install community.general`

Requirements
----------

* Ansible and community.general collection need to be installed

Usage
----------
A set of playbook examples is provided under the ansible-playbooks directory of this project.

* Common variables
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Variable "baseuri" represent BMC IP address, and variable "username" and "password" are used for BMC authentification. They should be configured in your inventory file before starting use playbooks. The results of get action playbooks which start with "get_" would be saved to files which's format is defined in create_output_file.yml. Please set variable "rootdir" to a local directory where you want to place results.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

* Using the ansible playbook to get bios attributes

This example save the bios attributes of your myhosts to files (Default location is "output" named folder in current directory)

    cd ansible-playbooks
    ansible-playbook get_bios_attributes.yml

* Using the ansible playbook to restart server

This example reaceful restart servers defined in myhosts inventory file

    cd ansible-playbooks
    ansible-playbook power_graceful_restart.yml

Contributing
----------

1. Fork it!
2. Create your feature branch: `git checkout -b my-new-feature`
3. Commit your changes: `git commit -am 'Add some feature'`
4. Push to the branch: `git push origin my-new-feature`
5. Submit a pull request :D

Copyright and License
---------------------

Copyright 2021 Lenovo Corporation

Licensed under the Apache License, Version 2.0 (the "License"); you may
not use this file except in compliance with the License. You may obtain
a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
License for the specific language governing permissions and limitations
under the License.
