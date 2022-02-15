###
#
# Lenovo Redfish examples - Reset System with the selected Reset Type
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


def set_power_state(ip, login_account, login_password, system_id, reset_type):
    """Reset system    
    :params ip: BMC IP address
    :type ip: string
    :params login_account: BMC user name
    :type login_account: string
    :params login_password: BMC user password
    :type login_password: string
    :params system_id: ComputerSystem instance id(None: first instance, All: all instances)
    :type system_id: None or string
    :params reset_type: reset system type by user specified
    :type reset_type: string
    :returns: returns reset system type result when succeeded or error message when failed
    """
    result = {}
    login_host = "https://" + ip
    try:
        # Connect using the address, account name, and password
        # Create a REDFISH object
        REDFISH_OBJ = redfish.redfish_client(base_url=login_host, username=login_account, timeout=utils.g_timeout,
                                             password=login_password, default_prefix='/redfish/v1', cafile=utils.g_CAFILE)
        # Login into the server and create a session
        REDFISH_OBJ.login(auth=utils.g_AUTH)
    except Exception as e:
        traceback.print_exc()
        result = {'ret': False, 'msg': "Error_message: %s. Please check if username, password and IP are correct" % repr(e)}
        return result

    try:
        # GET the ComputerSystem resource
        system = utils.get_system_url("/redfish/v1", system_id,  REDFISH_OBJ)
        if not system:
            result = {'ret': False, 'msg': "This system id is not exist or system member is None"}
            REDFISH_OBJ.logout()
            return result
        for i in range(len(system)):
            system_url = system[i]
            # GET the ComputerSystem resource
            response_system_url = REDFISH_OBJ.get(system_url, None)
            if response_system_url.status == 200:
                # Find the Reset Action target URL
                target_url = response_system_url.dict["Actions"]["#ComputerSystem.Reset"]["target"]
                # Prepare POST body
                post_body = {"ResetType": reset_type}
                # POST Reset Action
                post_response = REDFISH_OBJ.post(target_url, body=post_body)
                # If Response return 200/OK, return successful , else print the response Error code
                if post_response.status in [200, 202, 204]:
                    result = {'ret': True, 'msg': "reset system '%s' successful" % reset_type}
                else:
                    error_message = utils.get_extended_error(post_response)
                    result = {'ret': False, 'msg': "Url '%s' response Error code %s \nerror_message: %s" % (
                        target_url, post_response.status, error_message)}
                    return result
            else:
                error_message = utils.get_extended_error(response_system_url)
                result = {'ret': False, 'msg': "Url '%s' response Error code %s \nerror_message: %s" % (
                system_url, response_system_url.status, error_message)}
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


def add_helpmessage(argget):
    argget.add_argument('--resettype', type=str, required=True, help='Input the reset system type("On", "Nmi", "GracefulShutdown", "GracefulRestart", "ForceOn", "ForceOff", "ForceRestart")')


def add_parameter():
    """Add reset system parameter"""
    argget = utils.create_common_parameter_list()
    add_helpmessage(argget)
    args = argget.parse_args()
    parameter_info = utils.parse_parameter(args)
    parameter_info['reset_type'] = args.resettype
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
        reset_type = parameter_info['reset_type']
    except:
        sys.stderr.write("Please run the command 'python %s -h' to view the help info" % sys.argv[0])
        sys.exit(1)

    # Reset system result and check result
    result = set_power_state(ip, login_account, login_password,system_id, reset_type)
    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['msg'], sort_keys=True, indent=2))
    else:
        sys.stderr.write(result['msg'] + '\n')
        sys.exit(1)
