###
# Lenovo Redfish examples - Get bios boot mode
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
from . import lenovo_utils as utils


def get_bios_bootmode(ip, login_account, login_password, system_id):
    """Get bios boot mode
    :params ip: BMC IP address
    :type ip: string
    :params login_account: BMC user name
    :type login_account: string
    :params login_password: BMC user password
    :type login_password: string
    :params system_id: ComputerSystem instance id(None: first instance, All: all instances)
    :type system_id: None or string
    :returns: returns bios boot mode when succeeded or error message when failed
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

    try:
        # GET the ComputerSystem resource
        system = utils.get_system_url("/redfish/v1", system_id, REDFISH_OBJ)
        if not system:
            result = {'ret': False, 'msg': "This system id is not exist or system member is None"}
            return result

        for i in range(len(system)):
            system_url = system[i]
            response_system_url = REDFISH_OBJ.get(system_url, None)
            if response_system_url.status == 200:
                # Get the bios resource
                bios_url = response_system_url.dict['Bios']['@odata.id']
                response_bios_url = REDFISH_OBJ.get(bios_url, None)
                if response_bios_url.status != 200:
                    error_message = utils.get_extended_error(response_bios_url)
                    result = {'ret': False, 'msg': "Url '%s' response Error code %s \nerror_message: %s" % (bios_url, response_bios_url.status, error_message)}
                    return result
                else: # Get bios success
                    # Seek boot mode from bios attributes
                    attribute_bootmode = None
                    attributes = response_bios_url.dict['Attributes']
                    for attribute in attributes:
                        if attribute == "BootMode" or attribute == "SystemBootMode":
                            attribute_bootmode = attribute
                    if attribute_bootmode == None:
                        for attribute in attributes:
                            if "SystemBootMode" in attribute:
                                attribute_bootmode = attribute
                    if attribute_bootmode == None:
                        for attribute in attributes:
                            if "Boot Mode" in attribute or "Boot_Mode" in attribute:
                                attribute_bootmode = attribute
                    if attribute_bootmode == None:
                        result = {'ret': False, 'msg': "Can not found BootMode attribute in response of url %s" %(bios_url)}
                        return result
                    # Set output
                    boot_mode_dict = {}
                    boot_mode = response_bios_url.dict['Attributes'][attribute_bootmode]
                    boot_mode_dict["BootMode"] = boot_mode
                    result = {"ret": True, "msg":boot_mode_dict}
                    return result
            else:
                error_message = utils.get_extended_error(response_system_url)
                result = {'ret': False, 'msg': "Url '%s' response Error code %s \nerror_message: %s" % (system_url, response_system_url.status, error_message)}
                return result

    except Exception as e:
        result = {'ret':False, 'msg':"error_message:%s" %(e)}
    finally:
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

    # Get boot mode information and check result
    result = get_bios_bootmode(ip, login_account, login_password, system_id)
    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['msg'], sort_keys=True, indent=2))
    else:
        sys.stderr.write(result['msg'])
