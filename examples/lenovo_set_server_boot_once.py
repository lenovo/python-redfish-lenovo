###
#
# Lenovo Redfish examples - Reset System with the selected Reset Type
#
# Copyright Notice:
#
# Copyright 2018 Lenovo Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
###


import sys
import json
import redfish
import lenovo_utils as utils


def set_server_boot_once(ip, login_account, login_password, system_id, boot_source):
    """Set server boot once    
    :params ip: BMC IP address
    :type ip: string
    :params login_account: BMC user name
    :type login_account: string
    :params login_password: BMC user password
    :type login_password: string
    :params system_id: ComputerSystem instance id(None: first instance, All: all instances)
    :type system_id: None or string
    :params boot_source: Boot source type by user specified
    :type boot_source: string
    :returns: returns set server boot once result when succeeded or error message when failed
    """
    result = {}
    login_host = "https://" + ip
    try:
        # Connect using the address, account name, and password
        # Create a REDFISH object
        REDFISH_OBJ = redfish.redfish_client(base_url=login_host, username=login_account,
                                             password=login_password, default_prefix='/redfish/v1')
        # Login into the server and create a session
        REDFISH_OBJ.login(auth="session")
    except:
        sys.stdout.write("Please check the username, password, IP is correct\n")
        sys.exit(1)
    # GET the ComputerSystem resource
    system = utils.get_system_url("/redfish/v1",system_id, REDFISH_OBJ)
    if not system:
        result = {'ret': False, 'msg': "This system id is not exist or system member is None"}
        REDFISH_OBJ.logout()
        return result
    for i in range(len(system)):
        system_url = system[i]
        # Prepare PATCH Body to set Boot once to the user specified target
        patch_body = {"Boot": {"BootSourceOverrideEnabled": "", "BootSourceOverrideTarget": ""}}
        patch_body["Boot"]["BootSourceOverrideEnabled"] = "Once"
        patch_body["Boot"]["BootSourceOverrideTarget"] = boot_source
        patch_response = REDFISH_OBJ.patch(system_url, body=patch_body)
        # If Response does not return 200/OK, print the response Extended Error message
        if patch_response.status  == 200:
            result = {'ret': False, 'msg': "Set server boot once %s successful" % boot_source}
        else:
            message = utils.get_extended_error(patch_response)
            result = {'ret': False, 'msg': "Error message is %s" % message}
    # Logout of the current session
    REDFISH_OBJ.logout()
    return result


import argparse
def add_parameter():
    """Add set server boot source parameter"""
    argget = utils.create_common_parameter_list()
    argget.add_argument('--bootsource', type=str, help='Input the set server boot("None", "Pxe", "Cd", "Usb","Hdd","BiosSetup","Diags","UefiTarget")')
    args = argget.parse_args()
    parameter_info = utils.parse_parameter(args)
    return parameter_info


if __name__ == '__main__':
    # Get parameters from config.ini and/or command line
    parameter_info = add_parameter()

    # Get connection info from the parameters user specified
    ip = parameter_info['ip']
    login_account = parameter_info["user"]
    login_password = parameter_info["passwd"]
    system_id = parameter_info['sysid']

    # Get set info from the parameters user specified
    try:
        boot_source = parameter_info['boot_source']
    except:
        sys.stderr.write("Please run the command 'python %s -h' to view the help info" % sys.argv[0])
        sys.exit(1)

    # Set server boot once result and check result
    result = set_server_boot_once(ip, login_account, login_password, system_id, boot_source)
    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['entries'], sort_keys=True, indent=2))
    else:
        sys.stderr.write(result['msg'])









