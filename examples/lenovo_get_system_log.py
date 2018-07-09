###
#
# Lenovo Redfish examples - Get the system_log information
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


def get_system_log(ip, login_account, login_password, system_id):
    """Get system log    
    :params ip: BMC IP address
    :type ip: string
    :params login_account: BMC user name
    :type login_account: string
    :params login_password: BMC user password
    :type login_password: string
    :params system_id: ComputerSystem instance id(None: first instance, All: all instances)
    :type system_id: None or string
    :returns: returns system log when succeeded or error message when failed
    """
    result = {}
    login_host = 'https://' + ip
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

    # Get response_base_url resource
    response_base_url = REDFISH_OBJ.get('/redfish/v1', None)
    if response_base_url.status == 200:
        managers_url = response_base_url.dict['Managers']['@odata.id']
    else:
        result = {'ret': False, 'msg': "response base url Error code %s" % response_base_url.status}
        REDFISH_OBJ.logout()
        return result
    # Get Managers url resource
    response_managers_url = REDFISH_OBJ.get(managers_url, None)
    if response_managers_url.status == 200:
        manager_count = response_managers_url.dict['Members@odata.count']
    else:
        result = {'ret': False, 'msg': "response managers url Error code %s" % response_managers_url.status}
        REDFISH_OBJ.logout()
        return result
    for i in range(manager_count):
        manager_x_url = response_managers_url.dict['Members'][i]['@odata.id']
        response_manager_x_url = REDFISH_OBJ.get(manager_x_url, None)
        if response_manager_x_url.status == 200:
            log_services_url = response_manager_x_url.dict['LogServices']['@odata.id']
        else:
            result = {'ret': False, 'msg': "response managers url Error code %s" % response_manager_x_url.status}
            REDFISH_OBJ.logout()
            return result
        response_log_services_url = REDFISH_OBJ.get(log_services_url, None)
        if response_log_services_url.status == 200:
            # Get the log url collection
            members = response_log_services_url.dict['Members']
        else:
            result = {'ret': False, 'msg': "response_log_services_url Error code %s" % response_log_services_url.status}
            REDFISH_OBJ.logout()
            return result
        log_details = []
        for member in members:
            log_url = member['@odata.id']
            # Get the log url resource
            response_log_url = REDFISH_OBJ.get(log_url, None)
            if response_log_url.status == 200:
                entries_url = response_log_url.dict['Entries']['@odata.id']
                response_entries_url = REDFISH_OBJ.get(entries_url, None)
                if response_entries_url.status == 200:
                    # description = response_entries_url.dict['Description']
                    for logEntry in response_entries_url.dict['Members']:
                        entry = {}
                        name = logEntry['Name']
                        if 'Created' in logEntry:
                            created = logEntry['Created']
                        else:
                            created = ""
                        message = logEntry['Message']
                        severity = logEntry['Severity']

                        entry['Name'] = name
                        entry['Message'] = message
                        entry['Created'] = created
                        entry['Severity'] = severity
                        log_details.append(entry)
                else:
                    result = {'ret': False, 'msg': "response members url Error code %s" % response_entries_url.status}
                    REDFISH_OBJ.logout()
                    return result
                
            else:
                result = {'ret': False, 'msg': "response members url Error code %s" % response_log_url.status}
                REDFISH_OBJ.logout()
                return result
                
    result['ret'] = True            
    result['entries'] = log_details
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
    
    # Get system log and check result
    result = get_system_log(ip, login_account, login_password, system_id)
    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['entries'], sort_keys=True, indent=2))
    else:
        sys.stderr.write(result['msg'])