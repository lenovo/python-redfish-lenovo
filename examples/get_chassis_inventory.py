###
#
# Lenovo Redfish examples - get chassis inventory
# Copyright Notice:
#
# Copyright 2021 Lenovo Corporation
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


import redfish
import sys
import json
import traceback
import lenovo_utils as utils


def get_chassis_inventory(ip, login_account, login_password):
    """Get chassis inventory
    :params ip: BMC IP address
    :type ip: string
    :params login_account: BMC user name
    :type login_account: string
    :params login_password: BMC user password
    :type login_password: string
    :returns: returns get chassis inventory when succeeded or error message when failed
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
        result = {'ret': False, 'msg': "Please check the username, password, IP is correct\n"}
        return result

    try:
        chassis_details = []
        # Get ComputerBase resource
        response_base_url = REDFISH_OBJ.get('/redfish/v1', None)
        # Get response_base_url
        if response_base_url.status == 200:
            chassis_url = response_base_url.dict['Chassis']['@odata.id']
        else:
            error_message = utils.get_extended_error(response_base_url)
            result = {'ret': False, 'msg': "Url '/redfish/v1' response Error code %s \nerror_message: %s" % (
            response_base_url.status, error_message)}
            return result

        # Get response chassis url resource
        response_chassis_url = REDFISH_OBJ.get(chassis_url, None)
        if response_chassis_url.status == 200:
            # Get the chassis information
            for i in range(response_chassis_url.dict['Members@odata.count']):
                chassis_1_url = response_chassis_url.dict['Members'][i]['@odata.id']
                response_chassis_1_url = REDFISH_OBJ.get(chassis_1_url, None)
                if response_chassis_1_url.status == 200:
                    # if chassis is not normal skip it
                    if response_chassis_url.dict['Members@odata.count'] > 1 and \
                            ("Links" not in response_chassis_1_url.dict or
                             "ComputerSystems" not in response_chassis_1_url.dict["Links"] or
                             'Location' not in response_chassis_1_url.dict):
                        continue
                    chassis_inventory = response_chassis_1_url.dict
                    # Delete content with only url property
                    for property in ["Links", "@odata.etag", "@odata.id", "@odata.type", "LogServices",
                                 "Memory", "NetworkAdapters", "PCIeDevices", "PCIeSlots", "Power", "Thermal",
                                 "Controls", "EnvironmentMetrics", "PowerSubsystem", "Sensors", "ThermalSubsystem"]:
                        if property in chassis_inventory:
                            del chassis_inventory[property]
                    if "Oem" in chassis_inventory and "Lenovo" in chassis_inventory["Oem"]:
                        for property in ["LEDs", "Sensors", "Slots", "@odata.type"]:
                            if property in chassis_inventory["Oem"]["Lenovo"]:
                                del chassis_inventory["Oem"]["Lenovo"][property]

                    chassis_details.append(chassis_inventory)
                    result = {'ret': True, 'msg': chassis_details}
                    return result
                else:
                    error_message = utils.get_extended_error(response_chassis_1_url)
                    result = {'ret': False, 'msg': "Url '%s' response Error code %s \nerror_message: %s" % (
                        chassis_1_url, response_chassis_1_url.status, error_message)}
                    return result
        else:
            error_message = utils.get_extended_error(response_chassis_url)
            result = {'ret': False, 'msg': "Url '%s' response Error code %s \nerror_message: %s" % (chassis_url, response_chassis_url.status, error_message)}
            return result

    except Exception as e:
        traceback.print_exc()
        result = {'ret': False, 'msg': "error_message: %s" % e}
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

    # Get chassis inventory and check result
    result = get_chassis_inventory(ip, login_account, login_password)
    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['msg'], sort_keys=True, indent=2) + '\n')
    else:
        sys.stderr.write(result['msg'] + '\n')
        sys.exit(1)
