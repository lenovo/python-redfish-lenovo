###
#
# Lenovo Redfish examples - Set Bios attribute
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


def set_bios_attribute(ip, login_account, login_password, system_id, auth, attribute_name, attribute_value):
    """Set Bios attribute    
    :params ip: BMC IP address
    :type ip: string
    :params login_account: BMC user name
    :type login_account: string
    :params login_password: BMC user password
    :type login_password: string
    :params system_id: ComputerSystem instance id(None: first instance, All: all instances)
    :type system_id: None or string
    :params auth: Authentication mode(session or basic)
    :type auth: string
    :params attribute_name: Bios attribute name by user specified
    :type attribute_name: string
    :params attribute_value: Bios attribute value by user specified
    :type attribute_value: string
    :returns: returns set bios attribute result when succeeded or error message when failed
    """
    result = {}
    login_host = "https://" + ip
    try:
        # Connect using the BMC address, account name, and password
        # Create a REDFISH object
        REDFISH_OBJ = redfish.redfish_client(base_url=login_host, username=login_account,
                                             password=login_password, default_prefix='/redfish/v1')
        # Login into the server and create a session
        REDFISH_OBJ.login(auth=auth)
    except:
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

            parameter = {}
            for bios_attribute in bios_attribute_list:
                AttributeName = bios_attribute["AttributeName"]
                AttributeType = bios_attribute["Type"]
                if attribute_name == AttributeName:
                    if AttributeType == "Integer":
                        try:
                            attribute_value = int(attribute_value)
                            parameter = {attribute_name: attribute_value}
                        except:
                            result = {'ret': False, 'msg': "Please check the attribute value, this should be a number."}
                            return result
                    elif AttributeType == "Boolean":
                        if attribute_value.upper() == "TRUE":
                            parameter = {attribute_name: True}
                        elif attribute_value.upper() == "FALSE":
                            parameter = {attribute_name: False}
                        else:
                            result = {'ret': False, 'msg': "Please check the attribute value, this value is 'true' or 'false'."}
                            return result
                    else:
                        parameter = {attribute_name: attribute_value}
                    break
                else:
                    continue
            if parameter:
                attribute = {"Attributes": parameter}
            else:
                result = {"ret": False, "msg": "This bios attribute '%s' not supported on this platform" % attribute_name}
                return result
            headers = {"If-Match": "*", "Content-Type": "application/json"}
            response_pending_url = REDFISH_OBJ.patch(pending_url, headers = headers, body=attribute)
            if response_pending_url.status in [200,204]:
                result = {'ret': True, 'msg': '%s set Successful'% attribute_name }
            elif response_pending_url.status == 400:
                result = {'ret': False, 'msg': 'Not supported on this platform'}
            elif response_pending_url.status == 405:
                result = {'ret': False, 'msg': "Resource not supported"}
            else:
                error_message = utils.get_extended_error(response_pending_url)
                result = {'ret': False, 'msg': "Url '%s' response Error code %s \nerror_message: %s" % (
                    pending_url, response_pending_url.status, error_message)}
                return result
    except Exception as e:
        result = {'ret': False, 'msg': "error_message: %s" % (e)}
    finally:
        # Logout of the current session
        REDFISH_OBJ.logout()
        return result


import argparse
def add_helpmessage(parser):
    parser.add_argument('--name', type=str, required=True, help='Input the attribute name(This is the manufacturer/provider specific list of BIOS attributes.)')
    parser.add_argument('--value', type=str, required=True, help='Input the attribute value(This is the manufacturer/provider specific list of BIOS attributes.)')


def add_parameter():
    """Add set bios attribute parameter"""
    argget = utils.create_common_parameter_list()
    add_helpmessage(argget)
    args = argget.parse_args()
    parameter_info = utils.parse_parameter(args)
    parameter_info['attribute_name'] = args.name
    parameter_info['attribute_value'] = args.value
    return parameter_info


if __name__ == '__main__':
    # Get parameters from config.ini and/or command line
    parameter_info = add_parameter()

    # Get connection info from the parameters user specified
    ip = parameter_info['ip']
    login_account = parameter_info["user"]
    login_password = parameter_info["passwd"]
    system_id = parameter_info['sysid']
    auth = parameter_info['auth']

    # Get set info from the parameters user specified
    try:
        attribute_name = parameter_info['attribute_name']
        attribute_value = parameter_info['attribute_value']
    except:
        sys.stderr.write("Please run the command 'python %s -h' to view the help info" % sys.argv[0])
        sys.exit(1)

    # Set bios sttribute result and check result
    result = set_bios_attribute(ip, login_account, login_password, system_id, auth, attribute_name, attribute_value)
    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['msg'], sort_keys=True, indent=2))
    else:
        sys.stderr.write(result['msg'])
