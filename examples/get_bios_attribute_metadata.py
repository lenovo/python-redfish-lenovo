###
#
# Lenovo Redfish examples - Get Bios attribute metadata
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



import sys, os
import json
import redfish
from . import lenovo_utils as utils


def get_bios_attribute_metadata(ip, login_account, login_password, system_id):
    """Get bios attribute metadata    
    :params ip: BMC IP address
    :type ip: string
    :params login_account: BMC user name
    :type login_account: string
    :params login_password: BMC user password
    :type login_password: string
    :params system_id: ComputerSystem instance id(None: first instance, All: all instances)
    :type system_id: None or string
    :returns: returns bios attribute metadata when succeeded or error message when failed
    """
    result = {}
    login_host = "https://" + ip
    try:
        # Connect using the BMC address, account name, and password
        # Create a REDFISH object
        REDFISH_OBJ = redfish.redfish_client(base_url=login_host, username=login_account,
                                             password=login_password, default_prefix='/redfish/v1', cafile=utils.g_CAFILE)
        # Login into the server and create a session
        REDFISH_OBJ.login(auth=utils.g_AUTH)
    except:
        result = {'ret': False, 'msg': "Please check the username, password, IP is correct"}
        return result

    # GET the ComputerSystem resource
    system = utils.get_system_url("/redfish/v1", system_id, REDFISH_OBJ)
    if not system:
        result = {'ret': False, 'msg': "This system id is not exist or system member is None"}
        REDFISH_OBJ.logout()
        return result
    for i in range(len(system)):
        system_url = system[i]
        response_system_url = REDFISH_OBJ.get(system_url, None)
        if response_system_url.status == 200:
            if len(system) > 1 and 'Bios' not in response_system_url.dict:
                continue
            bios_url = response_system_url.dict['Bios']['@odata.id']
        else:
            result = {'ret': False, 'msg': "response system url Error code %s" % response_system_url.status}
            REDFISH_OBJ.logout()
            return result

        # Get Bios resource
        response_bios_url = REDFISH_OBJ.get(bios_url, None)
        if response_bios_url.status != 200:
            error_message = utils.get_extended_error(response_bios_url)
            result = {'ret': False, 'msg': "Url '%s' response error code %s \nerror_message: %s"
                                           % (bios_url, response_bios_url.status, error_message)}
            REDFISH_OBJ.logout()
            return result

        # Get used AttributeRegistry from Bios url
        attribute_registry = response_bios_url.dict['AttributeRegistry']

        # Find the AttributeRegistry json file uri from Registries
        registry_url = "/redfish/v1/Registries"
        registry_response = REDFISH_OBJ.get(registry_url, None)
        if registry_response.status != 200:
            error_message = utils.get_extended_error(registry_response)
            result = {'ret': False, 'msg': "Url '%s' response error code %s \nerror_message: %s"
                                           % (registry_url, registry_response.status, error_message)}
            REDFISH_OBJ.logout()
            return result
        bios_registry_url = None
        members_list = registry_response.dict["Members"]
        for registry in members_list:
            if attribute_registry in registry["@odata.id"]:
                bios_registry_url = registry["@odata.id"]
        if bios_registry_url is None:
            result = {'ret': False, 'msg': "Can not find %s in Registries" % (attribute_registry)}
            REDFISH_OBJ.logout()
            return result
        bios_registry_response = REDFISH_OBJ.get(bios_registry_url, None)
        if bios_registry_response.status != 200:
            error_message = utils.get_extended_error(bios_registry_response)
            result = {'ret': False, 'msg': "Url '%s' response error code %s \nerror_message: %s"
                                           % (bios_registry_url, bios_registry_response.status, error_message)}
            REDFISH_OBJ.logout()
            return result
        bios_registry_json_url = bios_registry_response.dict["Location"][0]["Uri"]

        # Download the AttributeRegistry json file
        bios_registry_json_response = REDFISH_OBJ.get(bios_registry_json_url, None)
        if bios_registry_json_response.status != 200:
            error_message = utils.get_extended_error(bios_registry_json_response)
            result = {'ret': False, 'msg': "Url '%s' response error code %s \nerror_message: %s"
                                           % (bios_registry_json_url, bios_registry_json_response.status, error_message)}
            REDFISH_OBJ.logout()
            return result
        filename = os.getcwd() + os.sep + bios_registry_json_url.split("/")[-1]
        with open(filename, 'w') as f:
            json.dump(bios_registry_json_response.dict, f, indent=2)
        result = {'ret': True, 'msg': "Download Bios AttributeRegistry file %s" % (bios_registry_json_url.split("/")[-1])}
        break

    # Logout of the current session
    try:
        REDFISH_OBJ.logout()
    except:
        pass
    return result


if __name__ == '__main__':
    # Get parameters from config.ini and/or command line
    argget = utils.create_common_parameter_list()
    args = argget.parse_args()
    parameter_info = utils.parse_parameter(args)
    
    # Get connection info from the parameters user specified
    ip = parameter_info['ip']
    login_account = parameter_info["user"]
    login_password = parameter_info["passwd"]
    system_id = parameter_info['sysid']
    
    # Get bios attribute metadata and check result
    result = get_bios_attribute_metadata(ip, login_account, login_password, system_id)
    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['msg'], sort_keys=True, indent=2))
    else:
        sys.stderr.write(result['msg'])
