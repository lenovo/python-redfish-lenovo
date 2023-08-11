###
#
# Lenovo Redfish examples - Set AMT(Advanced Memory Test)
#
# Copyright Notice:
#
# Copyright 2023 Lenovo Corporation
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
import traceback
import lenovo_utils as utils


def lenovo_set_amt(ip, login_account, login_password, system_id, enable_amt):
    """Enable or disable AMT(Advanced Memory Test)    
    :params ip: BMC IP address
    :type ip: string
    :params login_account: BMC user name
    :type login_account: string
    :params login_password: BMC user password
    :type login_password: string
    :params system_id: ComputerSystem instance id(None: first instance, All: all instances)
    :type system_id: None or string
    :params enable_amt: Enable or disable AMT
    :type enable_amt: int
    :returns: returns set memory AMT result when succeeded or error message when failed
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
            REDFISH_OBJ.logout()
            return result
        for i in range(len(system)):
            system_url = system[i]
            response_system_url = REDFISH_OBJ.get(system_url, None)
            if response_system_url.status == 200:
                # Get the ComputerBios resource
                bios_url = response_system_url.dict['Bios']['@odata.id']
                flag_sr645_sr665 = False
                if 'SR645' in response_system_url.dict['Model'] or 'SR665' in response_system_url.dict['Model']:
                    flag_sr645_sr665 = True
            else:
                error_message = utils.get_extended_error(response_system_url)
                result = {'ret': False, 'msg': "Url '%s' response Error code %s \nerror_message: %s" % (
                    system_url, response_system_url.status, error_message)}
                return result

            # Get bios url resource
            response_bios_url = REDFISH_OBJ.get(bios_url, None)
            if response_bios_url.status == 200:
                if "SettingsObject" in response_bios_url.dict['@Redfish.Settings'].keys():
                    pending_url = response_bios_url.dict['@Redfish.Settings']['SettingsObject']['@odata.id']
                else:
                    pending_url = bios_url + "/SD"
                attribute_registry = response_bios_url.dict['AttributeRegistry']
            else:
                error_message = utils.get_extended_error(response_bios_url)
                result = {'ret': False, 'msg': "Url '%s' response Error code %s \nerror_message: %s" % (
                    bios_url, response_bios_url.status, error_message)}
                return result
            
            registry_url = "/redfish/v1/Registries"
            registry_response = REDFISH_OBJ.get(registry_url, None)
            if registry_response.status == 200:
                members_list = registry_response.dict["Members"]
                for registry in members_list:
                    if attribute_registry in registry["@odata.id"]:
                        bios_registry_url = registry["@odata.id"]
            else:
                error_message = utils.get_extended_error(registry_response)
                result = {'ret': False, 'msg': "Url '%s' response Error code %s \nerror_message: %s" % (
                    registry_url, registry_response.status, error_message)}
                return result

            bios_registry_response = REDFISH_OBJ.get(bios_registry_url, None)
            if bios_registry_response.status == 200:
                bios_registry_json_url = bios_registry_response.dict["Location"][0]["Uri"]
            else:
                error_message = utils.get_extended_error(bios_registry_response)
                result = {'ret': False, 'msg': "Url '%s' response Error code %s \nerror_message: %s" % (
                    bios_registry_url, bios_registry_response.status, error_message)}
                return result

            bios_registry_json_response = REDFISH_OBJ.get(bios_registry_json_url, None)
            if bios_registry_json_response.status == 200:
                bios_attribute_list = bios_registry_json_response.dict["RegistryEntries"]["Attributes"]
            else:
                error_message = utils.get_extended_error(bios_registry_json_response)
                result = {'ret': False, 'msg': "Url '%s' response Error code %s \nerror_message: %s" % (
                    bios_registry_json_url, bios_registry_json_response.status, error_message)}
                return result
            
            memory_test_value_enum = []
            watchdog_value_enum = []
            for bios_attribute in bios_attribute_list:
                AttributeName = bios_attribute["AttributeName"]
                if "Memory_MemoryTest" == AttributeName:
                    AttributeValue = bios_attribute["Value"]
                    for value in AttributeValue:
                        memory_test_value_enum.append(value["ValueName"])
                if "SystemRecovery_POSTWatchdogTimer" == AttributeName:
                    AttributeValue = bios_attribute["Value"]
                    for value in AttributeValue:
                        watchdog_value_enum.append(value["ValueName"])

            parameter = {}
            Memory_MemoryTest_Enable = "Enable"
            Memory_MemoryTest_Disable = "Disable"
            for value in memory_test_value_enum:
                if "Enable" in value:
                    Memory_MemoryTest_Enable = value    #Enable or Enabled
                if "Disable" in value:
                    Memory_MemoryTest_Disable = value

            POSTWatchdog_Enable = "Enable"
            POSTWatchdog_Disable = "Disable"
            for value in watchdog_value_enum:
                if "Enable" in value:
                    POSTWatchdog_Enable = value
                if "Disable" in value:
                    POSTWatchdog_Disable = value
            if enable_amt:
                parameter = {
                    "Attributes": {
                        "Memory_MemoryTest": Memory_MemoryTest_Enable,
                        "SystemRecovery_POSTWatchdogTimer": POSTWatchdog_Disable
                    }
                }
            else:
                parameter = {
                    "Attributes":{
                        "Memory_MemoryTest": Memory_MemoryTest_Disable,
                        "SystemRecovery_POSTWatchdogTimer": POSTWatchdog_Enable
                    }
                }

            if "Memory_MemoryTest" in response_bios_url.dict['Attributes'] and "Memory_AdvMemTestOptions" in response_bios_url.dict['Attributes']:
                if enable_amt:
                    parameter["Attributes"]["Memory_AdvMemTestOptions"] = 0xF000
                else:
                    parameter["Attributes"]["Memory_AdvMemTestOptions"] = 0
            else:
                if flag_sr645_sr665:
                    pending_url = system_url
                    if "Oem" in response_system_url.dict and "Lenovo" in response_system_url.dict["Oem"] and "UefiMemoryTest" in response_system_url.dict["Oem"]["Lenovo"]:
                        if enable_amt:
                            parameter = {
                                "Oem": {
                                    "Lenovo": {
                                        "UefiMemoryTest": {
                                            "Behavior": "Repair",       #Repair or Test
                                            "Policy": "Once"
                                        }
                                    }
                                }
                            }
                        else:
                            parameter = {
                                "Oem": {
                                    "Lenovo": {
                                        "UefiMemoryTest": {
                                            "Behavior": "Disable"
                                        }
                                    }
                                }
                            }
                    else:
                        result = {"ret": False, "msg": "AMT is not supported on this platform, the UefiMemoryTest is not supported on this platform" }
                        return result
                else:
                    bios_protected_url = "/redfish/v1/Systems/1/Bios/Actions/Oem/LenovoBios.GetProtectedAttributes"
                    bios_protected_response = REDFISH_OBJ.post(bios_protected_url, body={})
                    if bios_protected_response.status == 200:
                        set_protected_url = "/redfish/v1/Systems/1/Bios/Actions/Oem/LenovoBios.SetProtectedAttributes"
                        body = {"Attributes":{}}
                        if enable_amt:
                            body["Attributes"]["Memory_AdvMemTestOptions"] = 0xF000
                        else:
                            body["Attributes"]["Memory_AdvMemTestOptions"] = 0
                        set_protected_response = REDFISH_OBJ.post(set_protected_url, body=body)
                        if set_protected_response.status == 200:
                            msg = 'Disable AMT from LenovoBios.SetProtectedAttributes successful.'
                            if enable_amt:
                                msg = 'Enable AMT from LenovoBios.SetProtectedAttributes successful.'
                            # print(msg)
                        else:
                            error_message = utils.get_extended_error(registry_response)
                            result = {'ret': False, 'msg': "Url '%s' response Error code %s \nerror_message: %s" % (
                                registry_url, registry_response.status, error_message)}
                            return result
                    elif bios_protected_response.status == 404:
                        result = {"ret": False, "msg": "AMT is not supported on this platform, the bios attribute Memory_MemoryTest or Memory_AdvMemTestOptions is not supported on this platform" }
                        return result
                    else:
                        error_message = utils.get_extended_error(registry_response)
                        result = {'ret': False, 'msg': "Url '%s' response Error code %s \nerror_message: %s" % (
                            registry_url, registry_response.status, error_message)}
                        return result

            headers = {"If-Match": "*", "Content-Type": "application/json"}
            response_pending_url = REDFISH_OBJ.patch(pending_url, headers = headers, body=parameter)
            if response_pending_url.status in [200,204]:
                msg = 'Disable AMT successful'
                if enable_amt:
                    msg = 'Enable AMT successful, need to reboot system to start AMT.'
                result = {'ret': True, 'msg': msg}
            else:
                error_message = utils.get_extended_error(response_pending_url)
                result = {'ret': False, 'msg': "Url '%s' response Error code %s \nerror_message: %s" % (
                    pending_url, response_pending_url.status, error_message)}
                return result
    except Exception as e:
        traceback.print_exc()
        result = {'ret': False, 'msg': "error_message: %s" % (e)}
    finally:
        # Logout of the current session
        try:
            REDFISH_OBJ.logout()
        except:
            pass
        return result


import argparse
def add_helpmessage(parser):
    parser.add_argument('--enable_amt', type=int,  choices=[0, 1], required=True, help='Disable or Enable AMT, 0: Disable, 1: Enable.')

def add_parameter():
    """Add enable amt parameter"""
    argget = utils.create_common_parameter_list()
    add_helpmessage(argget)
    args = argget.parse_args()
    parameter_info = utils.parse_parameter(args)
    parameter_info['enable_amt'] = args.enable_amt
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
    enable_amt = bool(parameter_info['enable_amt'])

    # Set amt result and check result
    result = lenovo_set_amt(ip, login_account, login_password, system_id, enable_amt)
    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['msg'], sort_keys=True, indent=2))
    else:
        sys.stderr.write(result['msg'] + '\n')
        sys.exit(1)
