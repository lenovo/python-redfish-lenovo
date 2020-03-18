###
#
# Lenovo Redfish examples - Set bios password
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


def set_bios_password(ip, login_account, login_password, system_id, bios_password_name, bios_password, oldbiospass):
    """Set Bios password
    :params ip: BMC IP address
    :type ip: string
    :params login_account: BMC user name
    :type login_account: string
    :params login_password: BMC user password
    :type login_password: string
    :params system_id: ComputerSystem instance id(None: first instance, All: all instances)
    :type system_id: None or string
    :params bios_password_name: Bios password name by user specified
    :type bios_password_name: string
    :params bios_password: Bios password by user specified
    :type bios_password: string
    :params oldbiospass: Old Bios password
    :type oldbiospass: None or string
    :returns: returns set bios password result when succeeded or error message when failed
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
        system = utils.get_system_url("/redfish/v1",system_id, REDFISH_OBJ)
        if not system:
            result = {'ret': False, 'msg': "This system id is not exist or system member is None"}
            return result

        for i in range(len(system)):
            system_url = system[i]
            response_system_url = REDFISH_OBJ.get(system_url, None)
            if response_system_url.status == 200:
                # Get the ComputerBios resource
                if len(system) > 1 and 'Bios' not in response_system_url.dict:
                    continue
                bios_url = response_system_url.dict['Bios']['@odata.id']
            else:
                error_message = utils.get_extended_error(response_system_url)
                result = {'ret': False, 'msg': "Url '%s' response Error code %s \nerror_message: %s" % (
                    system_url, response_system_url.status, error_message)}
                return result

            response_bios_url = REDFISH_OBJ.get(bios_url, None)
            if response_bios_url.status == 200:
                # Get password name allowable value list
                attribute_registry = response_bios_url.dict['AttributeRegistry']
                registry_url = "/redfish/v1/Registries"
                bios_registry_url = ""
                registry_response = REDFISH_OBJ.get(registry_url, None)
                if registry_response.status == 200:
                    members_list = registry_response.dict["Members"]
                    for registry in members_list:
                        if attribute_registry in registry["@odata.id"]:
                            bios_registry_url = registry["@odata.id"]
                bios_registry_json_url = ""
                if bios_registry_url != "":
                    bios_registry_response = REDFISH_OBJ.get(bios_registry_url, None)
                    if bios_registry_response.status == 200:
                        bios_registry_json_url = bios_registry_response.dict["Location"][0]["Uri"]
                bios_attribute_list = None
                if bios_registry_json_url != "":
                    bios_registry_json_response = REDFISH_OBJ.get(bios_registry_json_url, None)
                    if bios_registry_json_response.status == 200:
                        bios_attribute_list = bios_registry_json_response.dict["RegistryEntries"]["Attributes"]

                password_allowed_values = []
                for bios_attribute in bios_attribute_list:
                    AttributeName = bios_attribute["AttributeName"]
                    AttributeType = bios_attribute["Type"]
                    if AttributeType == "Password":
                        password_allowed_values.append(AttributeName)

                if len(password_allowed_values) == 0:
                    if "PasswordName@Redfish.AllowableValues" in response_bios_url.dict["Actions"]["#Bios.ChangePassword"]:
                        password_allowed_values = response_bios_url.dict["Actions"]["#Bios.ChangePassword"]["PasswordName@Redfish.AllowableValues"]

                # Check whether password name is in allowable value list  
                if len(password_allowed_values) != 0 and bios_password_name not in password_allowed_values:
                    result = {'ret': False, 'msg': "Specified password name is not included in allowable value list. Please select password name from list: %s" % (str(password_allowed_values))}
                    return result

                # get parameter requirement if ActionInfo is provided
                if "@Redfish.ActionInfo" in response_bios_url.dict["Actions"]["#Bios.ChangePassword"]:
                    actioninfo_url = response_bios_url.dict["Actions"]["#Bios.ChangePassword"]["@Redfish.ActionInfo"]
                    response_actioninfo_url = REDFISH_OBJ.get(actioninfo_url, None)
                    if (response_actioninfo_url.status == 200) and ("Parameters" in response_actioninfo_url.dict):
                        for parameter in response_actioninfo_url.dict["Parameters"]:
                            if ("OldPassword" == parameter["Name"]) and (True == parameter["Required"]):
                                if oldbiospass == None:
                                    result = {'ret': False, 'msg': "Required parameter oldbiospasswd need to be specified."}
                                    return result

                # Get the change password url
                change_password_url = response_bios_url.dict['Actions']['#Bios.ChangePassword']['target']

                # Set Password info
                requestbody = {}
                PasswordName = bios_password_name
                new_password = bios_password
                if oldbiospass == None:
                    requestbody = {"PasswordName":PasswordName, "NewPassword":new_password}
                else:
                    requestbody = {"PasswordName":PasswordName, "NewPassword":new_password, "OldPassword":oldbiospass}

                # Change password
                response_change_password = REDFISH_OBJ.post(change_password_url, body=requestbody)
                if response_change_password.status in [200, 204]:
                    result = {'ret': True, 'msg': 'Setting BIOS password successfully'}
                else:
                    error_message = utils.get_extended_error(response_change_password)
                    result = {'ret': False, 'msg': "Url '%s' response Error code %s \nerror_message: %s" % (
                        change_password_url, response_change_password.status, error_message)}
                    return result
            else:
                error_message = utils.get_extended_error(response_bios_url)
                result = {'ret': False, 'msg': "Url '%s' response Error code %s \nerror_message: %s" % (
                    bios_url, response_bios_url.status, error_message)}
                return result

    except Exception as e:
        result = {'ret': False, 'msg': "error_message: %s" % (e)}
    finally:
        # Logout of the current session
        REDFISH_OBJ.logout()
        return result


import argparse
def add_helpmessage(parser):
    parser.add_argument('--name', type=str, required=True, help='Input the bios password name (Such as "UefiAdminPassword", "UefiPowerOnPassword")')
    parser.add_argument('--biospasswd', type=str, required=True, help='Input the new bios password. Input null string "" if you want to clear the password')
    parser.add_argument('--oldbiospasswd', type=str, default=None, help='Input the old bios password if needed')


def add_parameter():
    """Add set bios password parameter"""
    argget = utils.create_common_parameter_list()
    add_helpmessage(argget)
    args = argget.parse_args()
    parameter_info = utils.parse_parameter(args)
    parameter_info['bios_password_name'] = args.name
    parameter_info['bios_password'] = args.biospasswd
    parameter_info['bios_oldpassword'] = args.oldbiospasswd
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
    try:
        bios_password_name = parameter_info['bios_password_name']
        bios_password = parameter_info['bios_password']
        bios_oldpassword = parameter_info['bios_oldpassword']
    except:
        sys.stderr.write("Please run the command 'python %s -h' to view the help info" % sys.argv[0])
        sys.exit(1)

    # Set bios password result and check result
    result = set_bios_password(ip, login_account, login_password, system_id, bios_password_name, bios_password, bios_oldpassword)
    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['msg'], sort_keys=True, indent=2))
    else:
        sys.stderr.write(result['msg'])
