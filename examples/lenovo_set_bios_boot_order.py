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
import lenovo_utils as utils


def set_bios_boot_order(ip, login_account, login_password, system_id, auth, bootorder):
    """set bios boot order
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
    :params bootorder: Specify the bios boot order list,  The boot order takes effect on the next startup
    :type bootorder: list
    :returns: returns set bios boot order result when succeeded or error message when failed
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
        # Get the ComputerSystem resource
        system = utils.get_system_url("/redfish/v1", system_id, REDFISH_OBJ)
        if not system:
            result = {'ret': False, 'msg': "This system id is not exist or system member is None"}
            return result

        for i in range(len(system)):
            system_url = system[i]
            response_system_url = REDFISH_OBJ.get(system_url, None)
            if response_system_url.status == 200:
                # Get the BootSettings url
                boot_settings_url = response_system_url.dict['Oem']['Lenovo']['BootSettings']['@odata.id']
            else:
                error_message = utils.get_extended_error(response_system_url)
                result = {'ret': False, 'msg': "Url '%s' response Error code %s \nerror_message: %s" % (system_url, response_system_url.status, error_message)}
                return result

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
                        result = {'ret': False, 'msg': "You can specify one or more boot order form list:%s" %boot_order_supported}
                        return result

            # Set the boot order next via patch request
            body = {"BootOrderNext":bootorder}
            response_boot_order = REDFISH_OBJ.patch(boot_order_url, body=body)
            if response_boot_order.status == 200:
                boot_order_next = response_boot_order.dict["BootOrderNext"]
                result = {'ret': True, 'msg': "Modified Boot Order '%s' successfully"%(boot_order_next)}
            else:
                error_message = utils.get_extended_error(response_boot_order)
                result = {'ret': False, 'msg': "Url '%s' response Error code %s \nerror_message: %s" % (
                    boot_order_url, response_boot_order.status, error_message)}
                return result
    except Exception as e:
        result = {'ret':False, 'msg':"error_message:%s" %(e)}
    finally:
        # Logout of the current session
        REDFISH_OBJ.logout()
        return result


def add_helpmessage(argget):
    argget.add_argument('--bootorder', nargs='*', type=str, required=True, help='Input the bios boot order list,  The boot order takes effect on the next startup. Support:"CD/DVD Rom","Hard Disk", etc.')


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
    auth = parameter_info['auth']

    # Get set info from the parameters user specified
    try:
        bootorder = parameter_info["bootorder"]
    except:
        sys.stderr.write("Please run the command 'python %s -h' to view the help info" % sys.argv[0])
        sys.exit(1)

    # Get set bios boot order result and check result
    result = set_bios_boot_order(ip, login_account, login_password, system_id, auth, bootorder)
    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['msg'], sort_keys=True, indent=2))
    else:
        sys.stderr.write(result['msg'])
