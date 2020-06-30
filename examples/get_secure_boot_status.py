###
#
# Lenovo Redfish examples - Get secure boot status
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
import redfish
import lenovo_utils as utils
import json


def get_secure_boot_status(ip, login_account, login_password, system_id):
    """Get secure boot status    
    :params ip: BMC IP address
    :type ip: string
    :params login_account: BMC user name
    :type login_account: string
    :params login_password: BMC user password
    :type login_password: string
    :params system_id: ComputerSystem instance id(None: first instance, All: all instances)
    :type system_id: None or string
    :returns: returns secure boot status when succeeded or error message when failed
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
    secure_details = []
    system = utils.get_system_url("/redfish/v1", system_id, REDFISH_OBJ)
    if not system:
        result = {'ret': False, 'msg': "This system id is not exist or system member is None"}
        REDFISH_OBJ.logout()
        return result
    for i in range(len(system)):
        system_url = system[i]
        response_system_url = REDFISH_OBJ.get(system_url, None)
        if response_system_url.status != 200:
            error_message = utils.get_extended_error(response_system_url)
            result = {'ret': False, 'msg': "Url '%s' response Error code %s \nerror_message: %s" % (
                system_url, response_system_url.status, error_message)}
            REDFISH_OBJ.logout()
            return result

        if 'SecureBoot' not in response_system_url.dict:
            continue

        secure_boot_url = response_system_url.dict['SecureBoot']['@odata.id']    
        # Get the secure boot url resource
        response_secure_boot_url = REDFISH_OBJ.get(secure_boot_url, None)
        if response_secure_boot_url.status == 200:
            secure = {}
            for property in ["SecureBootEnable", "SecureBootMode"]:
                if property in response_secure_boot_url.dict:
                    secure[property] = response_secure_boot_url.dict[property]
                else:
                    secure[property] = None
            secure_details.append(secure)
        else:
            error_message = utils.get_extended_error(response_secure_boot_url)
            result = {'ret': False, 'msg': "Url '%s' response Error code %s \nerror_message: %s" % ( 
                secure_boot_url, response_secure_boot_url.status, error_message)}
            REDFISH_OBJ.logout()
            return result

    if len(secure_details) == 0:
        result = {'ret': False, 'msg': "Not support SecureBoot"}
    else:
        result['ret'] = True
        result['entries'] = secure_details
    # Logout of the current session
    REDFISH_OBJ.logout()
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
    
    # Get secure boot status and check result
    result = get_secure_boot_status(ip, login_account, login_password, system_id)
    
    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['entries'], sort_keys=True, indent=2))
    else:
        sys.stderr.write(result['msg'])
