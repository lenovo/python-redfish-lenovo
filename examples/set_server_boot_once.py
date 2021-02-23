###
#
# Lenovo Redfish examples - Set server boot once
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


def set_server_boot_once(ip, login_account, login_password, system_id, boot_source, mode):
    """Set server boot once    
    :params ip: BMC IP address
    :type ip: string
    :params login_account: BMC user name
    :type login_account: string
    :params login_password: BMC user password
    :type login_password: string
    :params system_id: ComputerSystem instance id(None: first instance, All: all instances)
    :type system_id: None or string
    :params boot_source: Boot source type by user specified
    :type boot_source: string
    :params mode: Boot mode
    :type mode: string
    :returns: returns set server boot once result when succeeded or error message when failed
    """
    result = {}
    login_host = "https://" + ip
    try:
        # Connect using the address, account name, and password
        # Create a REDFISH object
        REDFISH_OBJ = redfish.redfish_client(base_url=login_host, username=login_account,
                                             password=login_password, default_prefix='/redfish/v1', cafile=utils.g_CAFILE)
        # Login into the server and create a session
        REDFISH_OBJ.login(auth=utils.g_AUTH)
    except:
        traceback.print_exc()
        sys.stdout.write("Please check the username, password, IP is correct\n")
        sys.exit(1)
    try:
        # GET the ComputerSystem resource
        system = utils.get_system_url("/redfish/v1",system_id, REDFISH_OBJ)
        if not system:
            result = {'ret': False, 'msg': "This system id is not exist or system member is None"}
            REDFISH_OBJ.logout()
            return result
        for i in range(len(system)):
            system_url = system[i]
            # get etag to set If-Match precondition
            response_system_url = REDFISH_OBJ.get(system_url, None)
            if response_system_url.status != 200:
                error_message = utils.get_extended_error(response_system_url)
                result = {'ret': False, 'msg': "Url '%s' get failed. response Error code %s \nerror_message: %s" % (
                    system_url, response_system_url.status, error_message)}
                return result
            if "@odata.etag" in response_system_url.dict:
                etag = response_system_url.dict['@odata.etag']
            else:
                etag = ""
            headers = {"If-Match": etag}

            # Prepare PATCH Body to set Boot once to the user specified target
            patch_body = {"Boot": {"BootSourceOverrideEnabled": "", "BootSourceOverrideTarget": ""}}
            if boot_source == "None":
                patch_body["Boot"]["BootSourceOverrideEnabled"] = "Disabled"
            else:
                patch_body["Boot"]["BootSourceOverrideEnabled"] = "Once"
                patch_body["Boot"]["BootSourceOverrideTarget"] = boot_source
                if mode:
                    patch_body["Boot"]["BootSourceOverrideMode"] = mode

            patch_response = REDFISH_OBJ.patch(system_url, body=patch_body, headers=headers)

            # If Response does not return 200/OK or 204, print the response Extended Error message
            if patch_response.status in [200, 204]:
                result = {'ret': True, 'msg': "Set server boot once '%s' successfully" % boot_source}
            else:
                message = utils.get_extended_error(patch_response)
                result = {'ret': False, 'msg': "Url '%s' response Error code %s \n, Error message :%s" % (system_url, patch_response.status, message)}

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
def add_helpmessage(argget):
    argget.add_argument('--bootsource', type=str, choices=["None", "Pxe", "Cd", "Usb","Hdd","BiosSetup","Diags"], required=True, help='Specify the device for one-time boot at next server restart. The supported boot option(s) include :("None", "Pxe", "Cd", "Usb","Hdd","BiosSetup","Diags")')
    argget.add_argument('--mode', type=str, choices=["Legacy", "UEFI"], help='The BIOS boot mode to use when the system boots from one-time boot')


def add_parameter():
    """Add set server boot source parameter"""
    argget = utils.create_common_parameter_list()
    add_helpmessage(argget)
    args = argget.parse_args()
    parameter_info = utils.parse_parameter(args)
    parameter_info['boot_source'] = args.bootsource
    parameter_info['boot_mode'] = args.mode
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
    boot_source = parameter_info['boot_source']
    boot_mode = parameter_info['boot_mode']

    # Set server boot once result and check result
    result = set_server_boot_once(ip, login_account, login_password, system_id, boot_source, boot_mode)
    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['msg'], sort_keys=True, indent=2))
    else:
        sys.stderr.write(result['msg'] + '\n')









