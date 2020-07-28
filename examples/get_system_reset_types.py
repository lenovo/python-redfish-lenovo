###
#
# Lenovo Redfish examples - Get the current System Boot Once target
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


def get_system_reset_types(ip, login_account, login_password, system_id):
    """Get reset types    
    :params ip: BMC IP address
    :type ip: string
    :params login_account: BMC user name
    :type login_account: string
    :params login_password: BMC user password
    :type login_password: string
    :params system_id: ComputerSystem instance id(None: first instance, All: all instances)
    :type system_id: None or string
    :returns: returns reset types when succeeded or error message when failed
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
    reset_details = []
    system = utils.get_system_url("/redfish/v1", system_id, REDFISH_OBJ)
    if not system:
        result = {'ret': False, 'msg': "This system id is not exist or system member is None"}
        REDFISH_OBJ.logout()
        return result
    for i in range(len(system)):
        system_url = system[i]
        response_system_url = REDFISH_OBJ.get(system_url, None)
        if response_system_url.status == 200:
            # check whether Reset is supported
            if ("Actions" not in response_system_url.dict) or ("#ComputerSystem.Reset" not in response_system_url.dict["Actions"]):
                result = {'ret': False, 'msg': "Reset action is not supported."}
                REDFISH_OBJ.logout()
                return result

            # get AllowableValues for Reset action
            reset_types = {}
            if "ResetType@Redfish.AllowableValues" in response_system_url.dict["Actions"]["#ComputerSystem.Reset"]:
                Computer_reset = response_system_url.dict["Actions"]["#ComputerSystem.Reset"]["ResetType@Redfish.AllowableValues"]
                reset_types["ResetType@Redfish.AllowableValues"] = Computer_reset
                reset_details.append(reset_types)
            elif "@Redfish.ActionInfo" in response_system_url.dict["Actions"]["#ComputerSystem.Reset"]:
                actioninfo_url = response_system_url.dict["Actions"]["#ComputerSystem.Reset"]["@Redfish.ActionInfo"]
                response_actioninfo_url = REDFISH_OBJ.get(actioninfo_url, None)
                if response_actioninfo_url.status == 200:
                    if "Parameters" in response_actioninfo_url.dict:
                        for parameter in response_actioninfo_url.dict["Parameters"]:
                            if ("Name" in parameter) and (parameter["Name"] == "ResetType"):
                                if "AllowableValues" in parameter:
                                    reset_types["ResetType@Redfish.AllowableValues"] = parameter["AllowableValues"]
                                    reset_details.append(reset_types)
                else:
                    result = {'ret': False, 'msg': "Get url %s failed. Error code %s" % (actioninfo_url, response_actioninfo_url.status)}
                    REDFISH_OBJ.logout()
                    return result
            if "ResetType@Redfish.AllowableValues" not in reset_types:
                result = {'ret': False, 'msg': "No AllowableValues information found for Reset action."}
                REDFISH_OBJ.logout()
                return result
        else:
            result = {'ret': False, 'msg': "response_system_url Error code %s" % response_system_url.status}
            REDFISH_OBJ.logout()
            return result

    result['ret'] = True
    result['entries'] = reset_details
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
    system_id = parameter_info['sysid']
    
    # Get reset types and check result
    result = get_system_reset_types(ip, login_account, login_password, system_id)
    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['entries'], sort_keys=True, indent=2))
    else:
        sys.stderr.write(result['msg'] + '\n')

