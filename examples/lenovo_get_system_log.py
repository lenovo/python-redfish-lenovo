###
#
# Lenovo Redfish examples - Get the system_log information
#
# Copyright Notice:
#
# Copyright 2017 Lenovo Corporation
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
import lenovo_utils as utils


def connect_redfish_client(login_host, login_account, login_password):
    # Connect using the address, account name, and password

    ## Create a REDFISH object
    REDFISH_OBJ = redfish.redfish_client(base_url=login_host, username=login_account,
                                         password=login_password, default_prefix='/redfish/v1')

    # Login into the server and create a session
    REDFISH_OBJ.login(auth="session")
    return REDFISH_OBJ


def get_members_info(REDFISH_OBJ):
    result = {}
    log_details = []
    # GET the ComputerSystem resource
    system_url = utils.get_system_url("/redfish/v1", REDFISH_OBJ)
    response_system_url = REDFISH_OBJ.get(system_url, None)
    if response_system_url.status == 200:
        # Get the ComputerProcessors resource
        LogServices_url = response_system_url.dict['LogServices']['@odata.id']
        # print(LogServices_url)
    else:
        print("response_system_url Error code %s" % response_system_url.status)
        return
    response_logservices_url = REDFISH_OBJ.get(LogServices_url, None)
    if response_logservices_url.status == 200:
        members = response_logservices_url.dict['Members']
    else:
        print("response_logservices_url Error code %s" %response_logservices_url.status)
        return
    for member in members:
        log_url = member['@odata.id']
        temp_list = log_url.split('/')
        log_name = temp_list[-2]
        sys.stdout.write("===========================================%s===========================================\n" % log_name)
        response_log_url = REDFISH_OBJ.get(log_url, None)
        if response_log_url.status == 200:
            entries_url = response_log_url.dict['Entries']['@odata.id']
            response_entries_url = REDFISH_OBJ.get(entries_url, None)
            if response_entries_url.status == 200:
                description = response_entries_url.dict['Description']
                sys.stdout.write("decription :  %s\n" % description)
                for logEntry in response_entries_url.dict['Members']:
                    entry = {}
                    # I only extract some fields
                    name = logEntry['Name']
                    created = logEntry['Created']
                    message = logEntry['Message']
                    severity = logEntry['Severity']
                    sys.stdout.write("name:%s  created:%s  message:%s  serverity:%s\n" %(name, created, message, severity))
                    entry['name'] = name
                    entry['message'] = message
                    entry['created'] = created
                    entry['severity'] = severity
                    log_details.append(entry)
            else:
                result = {'ret': False, 'msg': "response_members_url Error code %s" % response_entries_url.status}
                REDFISH_OBJ.logout()
                return result
            result[log_name] = log_details
        else:
            result = {'ret': False, 'msg': "response_members_url Error code %s" % response_log_url.status}
            REDFISH_OBJ.logout()
            return result
    # Logout of the current session
    REDFISH_OBJ.logout()
    return result


if __name__ == '__main__':
    # login_host = 'https://10.245.39.185'
    # login_account = 'USERID'
    # login_password = 'PASSW0RD'
    login_host = 'https://' + sys.argv[1]
    login_account = sys.argv[2]
    login_password = sys.argv[3]
    REDFISH_OBJ = connect_redfish_client(login_host, login_account, login_password)
    get_members_info(REDFISH_OBJ)