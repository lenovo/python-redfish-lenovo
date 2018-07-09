###
#
# Lenovo Redfish examples - Get Bios attribute
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


def get_bios_attribute(ip, login_account, login_password, system_id, bios_get):
    """Get all bios attribute    
    :params ip: BMC IP address
    :type ip: string
    :params login_account: BMC user name
    :type login_account: string
    :params login_password: BMC user password
    :type login_password: string
    :params system_id: ComputerSystem instance id(None: first instance, All: all instances)
    :type system_id: None or string
    :returns: returns all bios attribute when succeeded or error message when failed
    """
    result = {}
    try:
        # Connect using the BMC address, account name, and password
        # Create a REDFISH object
        login_host = "https://" + ip
        REDFISH_OBJ = redfish.redfish_client(base_url=login_host, username=login_account,
                                             password=login_password, default_prefix='/redfish/v1')
        # Login into the server and create a session
        REDFISH_OBJ.login(auth="session")
    except:
        result = {'ret': False, 'msg': "Please check the username, password, IP is correct"}
        return result

    # GET the ComputerSystem resource
    system = utils.get_system_url("/redfish/v1", system_id, REDFISH_OBJ)
    if not system:
        result = {'ret': False, 'msg': "This system id is not exist or system member is None"}
        REDFISH_OBJ.logout()
        return result
    attributes = []
    for i in range(len(system)):
        system_url = system[i]
        response_system_url = REDFISH_OBJ.get(system_url, None)
        if response_system_url.status == 200:
            # Get the current url
            bios_url = response_system_url.dict['Bios']['@odata.id']
        else:
            result = {'ret': False, 'msg': "response system url Error code %s" % response_system_url.status}
            REDFISH_OBJ.logout()
            return result
        response_bios_url = REDFISH_OBJ.get(bios_url, None)
        if response_bios_url.status == 200:
            if bios_get == "current":
                # Get the bios url resource
                attribute = response_bios_url.dict['Attributes']
                attributes.append(attribute)
            elif bios_get == "pending":
                # Get pending url
                pending_url = response_bios_url.dict['@Redfish.Settings']['SettingsObject']['@odata.id']
                response_pending_url = REDFISH_OBJ.get(pending_url, None)
                if response_pending_url.status == 200:
                    # Get the pending url resource
                    attribute = response_pending_url.dict['Attributes']
                    attributes.append(attribute)
                else:
                    result = {'ret': False, 'msg': "response pending url Error code %s" % response_pending_url.status}
                    REDFISH_OBJ.logout()
                    return result
            else:
                result = {'ret': False, 'msg': "Please input '--bios current' or '--bios pending'"}
                REDFISH_OBJ.logout()
                return result
        else:
            result = {'ret': False, 'msg': "response bios url Error code %s" % response_bios_url.status}
            REDFISH_OBJ.logout()
            return result

    result['ret'] = True
    result['attributes'] = attributes
    REDFISH_OBJ.logout()
    return result


import argparse
def add_parameter():
    """Add get all bios attribute parameter"""
    argget = utils.create_common_parameter_list()
    argget.add_argument('--bios', default='current', type=str, help='Input the bios attribute get the current setting or the pending setting(current or pending)')
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
    system_id = parameter_info["sysid"]

    # Get set info from the parameters user specified
    try:
        bios_get = parameter_info['bios_get']
    except:
        sys.stderr.write("Please run the command 'python %s -h' to view the help info" % sys.argv[0])
        sys.exit(1)

    # Get all bios attribute and check result
    result = get_bios_attribute(ip, login_account, login_password, system_id, bios_get)
    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['attributes'], sort_keys=True, indent=2))
    else:
        sys.stderr.write(result['msg'])
