###
#
# Lenovo Redfish examples - Set bios boot order
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
import traceback
import lenovo_utils as utils


def lenovo_set_bios_boot_order(ip, login_account, login_password, system_id, bootorder):
    """set bios boot order
    :params ip: BMC IP address
    :type ip: string
    :params login_account: BMC user name
    :type login_account: string
    :params login_password: BMC user password
    :type login_password: string
    :params system_id: ComputerSystem instance id(None: first instance, All: all instances)
    :type system_id: None or string
    :params bootorder: Specify the bios boot order list,  The boot order takes effect on the next startup
    :type bootorder: list
    :returns: returns set bios boot order result when succeeded or error message when failed
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
        # Get the ComputerSystem resource
        system = utils.get_system_url("/redfish/v1", system_id, REDFISH_OBJ)
        if not system:
            result = {'ret': False, 'msg': "This system id is not exist or system member is None"}
            return result

        for i in range(len(system)):
            system_url = system[i]
            response_system_url = REDFISH_OBJ.get(system_url, None)
            if response_system_url.status != 200:
                error_message = utils.get_extended_error(response_system_url)
                result = {'ret': False, 'msg': "Url '%s' response Error code %s \nerror_message: %s" % (system_url, response_system_url.status, error_message)}
                return result

            # Set the boot order via Pending recourse
            if system_url.endswith("/"):
                pending_url = system_url + "Pending"
            else:
                pending_url = system_url + "/" + "Pending"
            # Get the Pending url
            response_pending_url = REDFISH_OBJ.get(pending_url, None)
            if response_pending_url.status == 200:
                # Get the boot order supported list via BootOptions
                supported_boot_id_name_map = {}
                if 'Boot' in str(response_system_url.dict) and 'BootOptions' in str(response_system_url.dict):
                    # Get the BootOptions url
                    boot_options_url = response_system_url.dict['Boot']['BootOptions']['@odata.id']
                    response_boot_options = REDFISH_OBJ.get(boot_options_url, None)
                    if response_boot_options.status != 200:
                        error_message = utils.get_extended_error(response_boot_options)
                        result = {'ret': False, 'msg': "Url '%s' response Error code %s \nerror_message: %s" % (
                            boot_options_url, response_boot_options.status, error_message)}
                        return result

                    # Get the mapping between boot Id and Name. Example: {"Boot0000": "CD/DVD"}
                    for member in response_boot_options.dict["Members"]:
                        boot_one_url = member['@odata.id']
                        response_boot_one_url = REDFISH_OBJ.get(boot_one_url, None)
                        if response_boot_one_url.status != 200:
                            error_message = utils.get_extended_error(response_boot_one_url)
                            result = {'ret': False, 'msg': "Url '%s' response Error code %s \nerror_message: %s" % (
                                boot_one_url, response_boot_one_url.status, error_message)}
                            return result
                        supported_boot_id_name_map[response_boot_one_url.dict["Id"]] = response_boot_one_url.dict["DisplayName"]
                
                boot_order_supported = []
                for name in supported_boot_id_name_map.values():
                    boot_order_supported.append(name)

                # Check input bootorder parmeter
                bootorder_ids = [] 
                for boot in bootorder:
                    if boot not in boot_order_supported:
                        result = {'ret': False, 'msg': "Invalid bootorder %s. You can specify one or more boot order form list: %s" %(boot, boot_order_supported)}
                        return result
                    for key, value in supported_boot_id_name_map.items():
                        if boot == value:
                            bootorder_ids.append(key)
                            break
                
                # Set the boot order via patch request
                body = {"Boot":{"BootOrder":bootorder_ids}}
                response_boot_order = REDFISH_OBJ.patch(pending_url, body=body)
                if response_boot_order.status == 200:
                    boot_order_next = response_boot_order.dict["Boot"]["BootOrder"]
                    boot_order_next_name = []
                    for id in boot_order_next:
                        if id in supported_boot_id_name_map.keys():
                            boot_order_next_name.append(supported_boot_id_name_map[id])
                        elif id[4:] in supported_boot_id_name_map.keys(): # For ThinkSystem SR635/SR655
                            boot_order_next_name.append(supported_boot_id_name_map[id[4:]])
                    result = {'ret': True, 'msg': "Modified Boot Order '%s' successfully. New boot order will take effect on the next startup."%(boot_order_next_name)}
                    return result
                else:
                    error_message = utils.get_extended_error(response_boot_order)
                    result = {'ret': False, 'msg': "Url '%s' response Error code %s \nerror_message: %s" % (
                        pending_url, response_boot_order.status, error_message)}
                    return result


            # Set boot order via Oem/Lenovo/BootSettings resource for ThinkSystem servers except SR635/SR655
            if 'Lenovo' in str(response_system_url.dict) and 'BootSettings' in str(response_system_url.dict):
                # Get the BootSettings url
                boot_settings_url = response_system_url.dict['Oem']['Lenovo']['BootSettings']['@odata.id']
                # Get the boot order settings url from boot settings resource
                response_boot_settings = REDFISH_OBJ.get(boot_settings_url, None)
                if response_boot_settings.status == 200:
                    boot_order_url = response_boot_settings.dict['Members'][0]['@odata.id']
                else:
                    error_message = utils.get_extended_error(response_boot_settings)
                    result = {'ret': False, 'msg': "Url '%s' response Error code %s \nerror_message: %s" % (
                        boot_settings_url, response_boot_settings.status, error_message)}
                    return result
    
                # Get the boot order supported list
                response_get_boot_order = REDFISH_OBJ.get(boot_order_url,None)
                if response_get_boot_order.status == 200:
                    boot_order_supported = response_get_boot_order.dict['BootOrderSupported']
                    for boot in bootorder:
                        if boot not in boot_order_supported:
                            result = {'ret': False, 'msg': "Invalid bootorder %s. You can specify one or more boot order form list:%s" %(boot, boot_order_supported)}
                            return result

                # Set the boot order next via patch request
                body = {"BootOrderNext":bootorder}
                response_boot_order = REDFISH_OBJ.patch(boot_order_url, body=body)
                if response_boot_order.status == 200:
                    boot_order_next = response_boot_order.dict["BootOrderNext"]
                    result = {'ret': True, 'msg': "Modified Boot Order '%s' successfully. New boot order will take effect on the next startup."%(boot_order_next)}
                    return result
                else:
                    error_message = utils.get_extended_error(response_boot_order)
                    result = {'ret': False, 'msg': "Url '%s' response Error code %s \nerror_message: %s" % (
                        boot_order_url, response_boot_order.status, error_message)}
                    return result

            # Set boot order via Bios Q00999_Boot_Option_Priorities attribute resource for ThinkSystem SR635/SR655
            if 'SR635' in str(response_system_url.dict) or 'SR655' in str(response_system_url.dict):
                # Get /redfish/v1/Systems/Self/Bios resource
                bios_url = response_system_url.dict['Bios']['@odata.id']
                response_bios = REDFISH_OBJ.get(bios_url, None)
                if response_bios.status != 200:
                    error_message = utils.get_extended_error(response_bios)
                    result = {'ret': False, 'msg': "Url '%s' response Error code %s \nerror_message: %s" % (
                        bios_url, response_bios.status, error_message)}
                    return result

                # Get current boot order setting from specified attribute
                attribute_name = 'Q00999_Boot_Option_Priorities'
                attribute_value = ''
                if 'Q00999_Boot_Option_Priorities' in response_bios.dict['Attributes']:
                    attribute_name = 'Q00999_Boot_Option_Priorities'
                    attribute_value = response_bios.dict['Attributes'][attribute_name]
                elif 'Q00999 Boot Option Priorities' in response_bios.dict['Attributes']:
                    attribute_name = 'Q00999 Boot Option Priorities'
                    attribute_value = response_bios.dict['Attributes'][attribute_name]
                else:
                    continue

                # Get supported boot order list
                boot_order_supported = list()
                org_boot_order_struct_list = attribute_value.split(';')
                if org_boot_order_struct_list[-1] == "":
                    org_boot_order_struct_list = org_boot_order_struct_list[:-1]
                for boot_order_struct in org_boot_order_struct_list:
                    boot_order_name = boot_order_struct.split(',')[0]
                    boot_order_supported.append(boot_order_name)

                # Set payload body
                body = {}
                new_boot_order_struct_list = list()
                for boot in bootorder:
                    # If input bootorder is not supported, prompt error message
                    if boot not in boot_order_supported:
                        result = {'ret': False, 'msg': "Invalid bootorder %s. You can specify one or more boot order form list:%s" %(boot, boot_order_supported)}
                        return result
                    # Add enabled bootorder list
                    for boot_order_struct in org_boot_order_struct_list:
                        boot_order_name = boot_order_struct.split(',')[0]
                        if boot == boot_order_name:
                            newstruct = boot_order_struct.replace('false', 'true')
                            if newstruct not in new_boot_order_struct_list:
                                new_boot_order_struct_list.append(newstruct)
                # Add disabled bootorder list
                for boot_order_struct in org_boot_order_struct_list:
                    boot_order_name = boot_order_struct.split(',')[0]
                    if boot_order_name not in bootorder:
                        newstruct = boot_order_struct.replace('true', 'false')
                        if newstruct not in new_boot_order_struct_list:
                            new_boot_order_struct_list.append(newstruct)
                new_boot_order_struct_string = ''
                for item in new_boot_order_struct_list:
                    new_boot_order_struct_string = new_boot_order_struct_string + item + ';'
                if new_boot_order_struct_string.endswith(";;"):
                    new_boot_order_struct_string = new_boot_order_struct_string[:-1]
                body = {"Attributes": {attribute_name: new_boot_order_struct_string}}
                headers = {"If-Match": '*'}

                # Set the boot order via patch request
                bios_settings_url = response_bios.dict['@Redfish.Settings']['SettingsObject']['@odata.id']
                response_bios_settings = REDFISH_OBJ.patch(bios_settings_url, body=body, headers=headers)
                if response_bios_settings.status in [200, 204]:
                    result = {'ret': True, 'msg': "Modified Boot Order successfully. New boot order will take effect on the next startup."}
                    return result
                else:
                    error_message = utils.get_extended_error(response_bios_settings)
                    result = {'ret': False, 'msg': "Url '%s' response Error code %s \nerror_message: %s" % (
                        bios_settings_url, response_bios_settings.status, error_message)}
                    return result

        result = {'ret': False, 'msg': "No related resource found, fail to set bios boot order for target server."}
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


def add_helpmessage(argget):
    argget.add_argument('--bootorder', nargs='*', type=str, required=True, help='Input the bios boot order list,  The boot order takes effect on the next startup. Support:"CD/DVD Rom","Hard Disk", etc. Use space to seperate them, example: "CD/DVD Rom" "Hard Disk"')


def add_parameter():
    """Add set bios boot order parameter"""
    argget = utils.create_common_parameter_list()
    add_helpmessage(argget)
    args = argget.parse_args()
    parameter_info = utils.parse_parameter(args)
    if args.bootorder is not None:
        parameter_info["bootorder"] = args.bootorder
    return parameter_info


if __name__ == '__main__':
    # Get parameters from config.ini and/or command line
    parameter_info = add_parameter()

    # Get connection info from the parameters user specified
    ip = parameter_info["ip"]
    login_account = parameter_info["user"]
    login_password = parameter_info["passwd"]
    system_id = parameter_info["sysid"]

    # Get set info from the parameters user specified
    try:
        bootorder = parameter_info["bootorder"]
    except:
        sys.stderr.write("Please run the command 'python %s -h' to view the help info" % sys.argv[0])
        sys.exit(1)

    # Get set bios boot order result and check result
    result = lenovo_set_bios_boot_order(ip, login_account, login_password, system_id, bootorder)
    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['msg'], sort_keys=True, indent=2))
    else:
        sys.stderr.write(result['msg'] + '\n')
        sys.exit(1)
