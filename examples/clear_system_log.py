###
#
# Lenovo Redfish examples - Clear System log
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


def clear_system_log(ip, login_account, login_password, system_id, type):
    """Clear system log    
    :params ip: BMC IP address
    :type ip: string
    :params login_account: BMC user name
    :type login_account: string
    :params login_password: BMC user password
    :type login_password: string
    :params system_id: ComputerSystem instance id(None: first instance, All: all instances)
    :type system_id: None or string
    :params type: The type of log to clear
    :type type: string
    :returns: returns clear system log result when succeeded or error message when failed
    """
    result = {}
    login_host = 'https://' + ip
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
        # Get response_base_url resource
        response_base_url = REDFISH_OBJ.get('/redfish/v1', None)
        if response_base_url.status != 200:
            error_message = utils.get_extended_error(response_base_url)
            result = {'ret': False, 'msg': "Url '/redfish/v1' response Error code %s \nerror_message: %s" % (response_base_url.status, error_message)}
            return result

        # Find target LogService url from specified resource type
        if type == "system":
            resource_url = response_base_url.dict['Systems']['@odata.id']
        elif type == "manager":
            resource_url = response_base_url.dict['Managers']['@odata.id']
        else:
            resource_url = response_base_url.dict['Chassis']['@odata.id']
        response_resource_url = REDFISH_OBJ.get(resource_url, None)
        if response_resource_url.status != 200:
            result = {'ret': False, 'msg': "response resource url %s failed. Error code %s" % (resource_url, response_resource_url.status)}
            return result
        resource_count = response_resource_url.dict['Members@odata.count']
        for i in range(resource_count):
            resource_x_url = response_resource_url.dict['Members'][i]['@odata.id']
            response_resource_x_url = REDFISH_OBJ.get(resource_x_url, None)
            if response_resource_x_url.status != 200:
                result = {'ret': False, 'msg': "response resource url %s failed. Error code %s" % (resource_x_url, response_resource_x_url.status)}
                return result
            if "LogServices" in response_resource_x_url.dict:
                log_services_url = response_resource_x_url.dict['LogServices']['@odata.id']
            else:
                if resource_count > 1:
                    continue
                result = {'ret': False, 'msg': "There is no LogServices in %s" % resource_x_url}
                return result

            # Clear log from LogServices
            response_log_services_url = REDFISH_OBJ.get(log_services_url, None)
            if response_log_services_url.status == 200:
                members = response_log_services_url.dict['Members']
            else:
                error_message = utils.get_extended_error(response_log_services_url)
                result = {'ret': False, 'msg': "Url '%s' response Error code %s \nerror_message: %s" % (log_services_url, response_log_services_url.status,error_message)}
                return result
            for member in members:
                log_url = member['@odata.id']
                response_log_url = REDFISH_OBJ.get(log_url, None)
                if "Actions" in response_log_url.dict:
                    if "#LogService.ClearLog" in response_log_url.dict["Actions"]:
                        # Get the clear system log url
                        clear_log_url = response_log_url.dict["Actions"]["#LogService.ClearLog"]["target"]
                        headers = {"Content-Type":"application/json"}

                        # Build request body and send requests to clear the system log
                        body = {}
                        # get parameter requirement if ActionInfo is provided
                        if "@Redfish.ActionInfo" in response_log_url.dict["Actions"]["#LogService.ClearLog"]:
                            actioninfo_url = response_log_url.dict["Actions"]["#LogService.ClearLog"]["@Redfish.ActionInfo"]
                            response_actioninfo_url = REDFISH_OBJ.get(actioninfo_url, None)
                            if (response_actioninfo_url.status == 200) and ("Parameters" in response_actioninfo_url.dict):
                                for parameter in response_actioninfo_url.dict["Parameters"]:
                                    if ("Name" in parameter) and ("AllowableValues" in parameter):
                                       body[parameter["Name"]] = parameter["AllowableValues"][0]
                        if not body:
                            body = {"Action": "LogService.ClearLog"}  #default body
                        response_clear_log = REDFISH_OBJ.post(clear_log_url, headers=headers, body=body)
                        if response_clear_log.status in [200, 204]:
                            result = {'ret': True, 'msg': "Clear log successfully"}
                        else:
                            error_message = utils.get_extended_error(response_clear_log)
                            result = {'ret': False, 'msg': "Url '%s' response Error code %s \nerror_message: %s" % (clear_log_url, response_clear_log.status, error_message)}
    except Exception as e:
        result = {'ret': False, 'msg': "error_message: %s" % (e)}
    finally:
        try:
            REDFISH_OBJ.logout()
        except:
            pass
        return result

import argparse
def add_helpmessage(parser):
    """Add clear system log parameter"""

    parser.add_argument('--type', type=str, default='system', choices=["system", "chassis", "manager"], help='Specify the type of the log to clear. Default is system')

    return parser

if __name__ == '__main__':
    # Get parameters from config.ini and/or command line
    argget = utils.create_common_parameter_list()
    argget = add_helpmessage(argget)
    args = argget.parse_args()
    parameter_info = utils.parse_parameter(args)
    
    # Get connection info from the parameters user specified
    ip = parameter_info['ip']
    login_account = parameter_info["user"]
    login_password = parameter_info["passwd"]
    system_id = parameter_info['sysid']
    
    # Get clear system log result and check result
    result = clear_system_log(ip, login_account, login_password, system_id, args.type)
    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['msg'], sort_keys=True, indent=2))
    else:
        sys.stderr.write(result['msg'])
