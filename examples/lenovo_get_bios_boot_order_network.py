###
#
# Lenovo Redfish examples - Get bios boot order of network
#
# Copyright Notice:
#
# Copyright 2024 Lenovo Corporation
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

import os
import sys
import json
import redfish
import traceback
import lenovo_utils as utils


def lenovo_get_bios_boot_order_network(ip, login_account, login_password, system_id):
    """Get bios boot order of network
    :params ip: BMC IP address
    :type ip: string
    :params login_account: BMC user name
    :type login_account: string
    :params login_password: BMC user password
    :type login_password: string
    :params system_id: ComputerSystem instance id(None: first instance, All: all instances)
    :type system_id: None or string
    :returns: returns bios boot order of network inventory when succeeded or error message when failed
    """
    result = {}
    login_host = "https://" + ip
    try:
        # Connect using the BMC address, account name, and password
        # Create a REDFISH object
        REDFISH_OBJ = redfish.redfish_client(base_url=login_host, username=login_account, timeout=utils.g_timeout,
                                             password=login_password, default_prefix='/redfish/v1', cafile=utils.g_CAFILE)
        # Login into the server and create a session
        REDFISH_OBJ.login(auth=utils.g_AUTH)
    except:
        traceback.print_exc()
        result = {'ret': False, 'msg': "Please check the username, password, IP is correct"}
        return result

    try:
        # GET the ComputerSystem resource
        system = utils.get_system_url("/redfish/v1", system_id, REDFISH_OBJ)
        if not system:
            result = {'ret': False, 'msg': "This system id is not exist or system member is None"}
            return result
        boot_info_list = []
        for i in range(len(system)):
            system_url = system[i]
            response_system_url = REDFISH_OBJ.get(system_url, None)
            if response_system_url.status != 200:
                error_message = utils.get_extended_error(response_system_url)
                result = {'ret': False, 'msg': "Url '%s' response Error code %s \nerror_message: %s" % (system_url, response_system_url.status, error_message)}
                return result

            # Get boot order network info via Oem/Lenovo/BootSettings resource for ThinkSystem servers except SR635/SR655
            if 'Lenovo' in str(response_system_url.dict) and 'BootSettings' in str(response_system_url.dict):
                # Get the BootSettings url
                boot_settings_url = response_system_url.dict['Oem']['Lenovo']['BootSettings']['@odata.id']
                response_boot_settings = REDFISH_OBJ.get(boot_settings_url, None)
                networkbootorder_url = ""
                if response_boot_settings.status == 200:
                    for member in response_boot_settings.dict["Members"]:
                        if "NetworkBootOrder" in member['@odata.id']:
                            networkbootorder_url = member['@odata.id']
                            break
                else:
                    error_message = utils.get_extended_error(response_boot_settings)
                    result = {'ret': False, 'msg': "Url '%s' response Error code %s \nerror_message: %s" % (
                        boot_settings_url, response_boot_settings.status, error_message)}
                    return result

                boot_order_info = {}
                # Get the boot order info via boot order recourse
                if networkbootorder_url != "":
                    response_boot_order = REDFISH_OBJ.get(networkbootorder_url, None)
                    if response_boot_order.status == 200:
                        boot_order_next = response_boot_order.dict['BootOrderNext']
                        boot_order_supported = response_boot_order.dict['BootOrderSupported']
                        boot_order_current = response_boot_order.dict['BootOrderCurrent']
                        boot_order_info['BootOrderNext'] = boot_order_next
                        boot_order_info['BootOrderSupported'] = boot_order_supported
                        boot_order_info['BootOrderCurrent'] = boot_order_current
                        boot_info_list.append(boot_order_info)
                        result['ret'] = True
                        result['entries'] = boot_info_list
                        return result
                    else:
                        error_message = utils.get_extended_error(response_boot_order)
                        result = {'ret': False, 'msg': "Url '%s' response Error code %s \nerror_message: %s" % (
                            networkbootorder_url, response_boot_order.status, error_message)}
                        return result


        result = {'ret': False, 'msg': "No related resource found, fail to get bios boot order of network for target server."}
        return result

    except Exception as e:
        traceback.print_exc()
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

    # Get bios boot order of network information and check result
    result = lenovo_get_bios_boot_order_network(ip, login_account, login_password, system_id)
    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['entries'], sort_keys=True, indent=2) + '\n')
    else:
        sys.stderr.write(result['msg'] + '\n')
        sys.exit(1)
