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
    result = {}
    log_details = []
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
    # GET the ComputerSystem resource
    system = utils.get_system_url("/redfish/v1",system_id, REDFISH_OBJ)
    if not system:
        result = {'ret': False, 'msg': "This system id is not exist or system member is None"}
        REDFISH_OBJ.logout()
        return result
    for i in range(len(system)):
        system_url = system[i]
        response_system_url = REDFISH_OBJ.get(system_url, None)
        if response_system_url.status == 200:
            # Get the ComputerProcessors resource
            LogServices_url = response_system_url.dict['LogServices']['@odata.id']
        else:
            result = {'ret': False, 'msg': "response system url Error code %s" % response_system_url.status}
            REDFISH_OBJ.logout()
            return result
        response_logservices_url = REDFISH_OBJ.get(LogServices_url, None)
        if response_logservices_url.status == 200:
            members = response_logservices_url.dict['Members']
        else:
            
            result = {'ret': False, 'msg': "response logservices url Error code %s" % response_logservices_url.status}
            REDFISH_OBJ.logout()
            return result

        for member in members:
            log_url = member['@odata.id']
            temp_list = log_url.split('/')
            log_name = temp_list[-2]
            response_log_url = REDFISH_OBJ.get(log_url, None)
            if response_log_url.status == 200:
                entries_url = response_log_url.dict['Entries']['@odata.id']
                response_entries_url = REDFISH_OBJ.get(entries_url, None)
                if response_entries_url.status == 200:
                    description = response_entries_url.dict['Description']
                    for logEntry in response_entries_url.dict['Members']:
                        entry = {}
                    
                        name = logEntry['Name']
                        created = logEntry['Created']
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
    # ip = '10.10.10.10'
    # login_account = 'USERID'
    # login_password = 'PASSW0RD'
    ip = sys.argv[1]
    login_account = sys.argv[2]
    login_password = sys.argv[3]
    try:
        system_id = sys.argv[4]
    except IndexError:
        system_id = None
    result = get_system_log(ip, login_account, login_password, system_id)
    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['entries'], sort_keys=True, indent=2))
    else:
        sys.stderr.write(result['msg'])