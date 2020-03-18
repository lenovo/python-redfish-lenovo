###
#
# Lenovo Redfish examples - set_bios_bootmode_legacy
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


import json, sys
import redfish
import lenovo_utils as utils


def set_bios_bootmode_legacy(ip, login_account, login_password, system_id):
    """Get set bios bootmode legacy result   
    :params ip: BMC IP address
    :type ip: string
    :params login_account: BMC user name
    :type login_account: string
    :params login_password: BMC user password
    :type login_password: string
    :params system_id: ComputerSystem instance id(None: first instance, All: all instances)
    :type system_id: None or string
    :returns: returns set bios bootmode legacy result when succeeded or error message when failed
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
        if response_system_url.status != 200:
            error_message = utils.get_extended_error(response_system_url)
            result = {'ret': False, 'msg': "Url '%s' response Error code %s \nerror_message: %s" % (system_url, response_system_url.status, error_message)}
            REDFISH_OBJ.logout()
            return result
        else:
            # Get the bios resource
            bios_url = response_system_url.dict['Bios']['@odata.id']
            response_bios_url = REDFISH_OBJ.get(bios_url, None)
            if response_bios_url.status != 200:
                error_message = utils.get_extended_error(response_bios_url)
                result = {'ret': False, 'msg': "Url '%s' response Error code %s \nerror_message: %s" % (bios_url, response_bios_url.status, error_message)}
                REDFISH_OBJ.logout()
                return result
            else: # Get bios success
                # Seek boot mode from bios attributes
                attribute_bootmode = None
                attributes = response_bios_url.dict['Attributes']
                for attribute in attributes:
                    if attribute == "BootMode" or attribute == "SystemBootMode":
                        attribute_bootmode = attribute
                        break
                if attribute_bootmode == None:
                    for attribute in attributes:
                        if "SystemBootMode" in attribute:
                            attribute_bootmode = attribute
                            break
                if attribute_bootmode == None:
                    for attribute in attributes:
                        if "Boot" in attribute and "Mode" in attribute:
                            attribute_bootmode = attribute
                            break
                if attribute_bootmode == None:
                    result = {'ret': False, 'msg': "Can not found BootMode attribute in response of url %s" %(bios_url)}
                    REDFISH_OBJ.logout()
                    return result

                # Get boot mode setting guide from bios registry
                WarningText = None
                ValueName = None
                bios_registry_url = "/redfish/v1/Registries/" + response_bios_url.dict['AttributeRegistry']
                response_bios_registry_url = REDFISH_OBJ.get(bios_registry_url, None)
                if response_bios_registry_url.status == 200:
                    locations = response_bios_registry_url.dict['Location']
                    bios_regjson_url = None
                    for location in locations:
                        if location['Language'] == 'en':
                            bios_regjson_url = location['Uri']
                            break
                    if bios_regjson_url:
                        response_bios_regjson_url = REDFISH_OBJ.get(bios_regjson_url, None)
                        if response_bios_regjson_url.status == 200:
                            regattributes = response_bios_regjson_url.dict['RegistryEntries']['Attributes']
                            for regattribute in regattributes:
                                if regattribute['AttributeName'] == attribute_bootmode:
                                    if 'WarningText' in regattribute:
                                        WarningText = regattribute['WarningText']
                                    for value in regattribute['Value']:
                                        if 'uefi' in value['ValueName'].lower():
                                            continue
                                        if 'legacy' in value['ValueName'].lower():
                                            ValueName = value['ValueName']
                                            break
                                        ValueName = value['ValueName']
                                    break
        
                # Perform patch to set
                if ValueName == None:
                    ValueName = "LegacyMode"
                pending_url = response_bios_url.dict['@Redfish.Settings']['SettingsObject']['@odata.id']
                parameter = {attribute_bootmode: ValueName}
                attribute = {"Attributes": parameter}
                headers = {"If-Match": '*'}
                response_pending_url = REDFISH_OBJ.patch(pending_url, body=attribute, headers=headers)
                if response_pending_url.status in [200,204]:
                    if WarningText:
                        result = {'ret': True, 'msg': 'set bios bootmode legacy successful. WarningText: %s'% (WarningText) }
                    else:
                        result = {'ret': True, 'msg': 'set bios bootmode legacy successful'}
                elif response_pending_url.status == 405:
                    result = {'ret': False, 'msg': "Resource not supported"}
                else:
                    error_message = utils.get_extended_error(response_pending_url)
                    result = {'ret': False, 'msg': "Url '%s' response Error code %s \nerror_message: %s" % (
                        pending_url, response_pending_url.status, error_message)}

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
    
    # Get set bios bootmode legacy result and check result
    result = set_bios_bootmode_legacy(ip, login_account, login_password, system_id)
    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['msg'], sort_keys=True, indent=2))
    else:
        sys.stderr.write(result['msg'])
