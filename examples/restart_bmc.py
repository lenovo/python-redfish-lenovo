###
#
# Lenovo Redfish examples - restart manager
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
import redfish
import json
import lenovo_utils as utils

def restart_manager(ip, login_account, login_password):
    """Get restart manager result    
    :params ip: BMC IP address
    :type ip: string
    :params login_account: BMC user name
    :type login_account: string
    :params login_password: BMC user password
    :type login_password: string
    :params system_id: ComputerSystem instance id(None: first instance, All: all instances)
    :type system_id: None or string
    :returns: returns restart manager result when succeeded or error message when failed
    """
    result = {}
    login_host = "https://"+ip
    try:
        # Connect using the BMC address, account name, and password
        # Create a REDFISH object
        REDFISH_OBJ = redfish.redfish_client(base_url=login_host, username=login_account,
                                             password=login_password, default_prefix='/redfish/v1')
        # Login into the server and create a session
        REDFISH_OBJ.login(auth="session")
    except:
        result = {'ret': False, 'msg': "Please check the username, password, IP is correct"}
        return result
    try:
        # GET the managers url from base url resource instance
        base_url = "/redfish/v1"
        response_base_url = REDFISH_OBJ.get(base_url, None)
        if response_base_url.status == 200:
            managers_url = response_base_url.dict['Managers']['@odata.id']
        else:
            error_message = utils.get_extended_error(response_base_url)
            result = {'ret': False, 'msg': "Url '/redfish/v1' response Error code %s \nerror_message: %s" % (response_base_url.status, error_message)}
            return result

        response_managers_url = REDFISH_OBJ.get(managers_url, None)
        if response_managers_url.status == 200:
            count = response_managers_url.dict["Members@odata.count"]
            # Get the manager url from Member list
            for i in range(count):
                manager_url = response_managers_url.dict['Members'][i]['@odata.id']
                response_manager_url = REDFISH_OBJ.get(manager_url, None)
                if response_manager_url.status == 200:
                    restart_manager_url = response_manager_url.dict['Actions']['#Manager.Reset']['target']
                    # Get resettype if the response manager resource instance contains Redfish.AllowableValues
                    try:
                        ResetType = response_manager_url.dict['Actions']['#Manager.Reset']['ResetType@Redfish.AllowableValues']
                    except:
                        ResetType = ''
                    # Build request body and send requests to restart manager
                    if 'GracefulRestart' in ResetType:
                        body = {'ResetType': 'GracefulRestart'}
                    elif 'ForceRestart' in ResetType:
                        body = {'ResetType': 'ForceRestart'}
                    else:
                        body = {"Action": "Manager.Reset"}
                    headers = {"Content-Type":"application/json"}
                    response_restart = REDFISH_OBJ.post(restart_manager_url, headers=headers, body=body)
                    if response_restart.status in [200, 204]:  
                        result = {'ret': True, 'msg': "Restart BMC Successfully"}
                    else:
                        error_message = utils.get_extended_error(response_restart)
                        result = {'ret': False, 'msg': "Restart BMC Falied, Url '%s' response Error code%s \nerror_message: %s" % (restart_manager_url, response_restart.status, error_message)}
                        return result
                else:
                    error_message = utils.get_extended_error(response_manager_url)
                    result = {'ret': False, 'msg': "Url '%s' response Error code %s \nerror_message: %s" % (manager_url, response_manager_url.status, error_message)}
                    return result
        else:
            error_message = utils.get_extended_error(response_managers_url)
            result = {'ret': False, 'msg': "Url '%s' response Error code %s \nerror_message: %s" % (managers_url, response_managers_url.status, error_message)}
            return result
    except Exception as e:
        result = {'ret': False, 'msg': "error_message: %s" % (e)}
    finally:
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
    
    # Get restart manager result and check result
    result = restart_manager(ip, login_account, login_password)
    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['msg'], sort_keys=True, indent=2))
    else:
        sys.stderr.write(result['msg'])