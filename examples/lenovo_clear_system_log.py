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


def clear_system_log(ip, login_account, login_password):
    result={}
    login_host = 'https://' + ip
    # Connect using the BMC address, account name, and password
    # Create a REDFISH object
    REDFISH_OBJ = redfish.redfish_client(base_url=login_host, username=login_account,
                                         password=login_password, default_prefix='/redfish/v1')
    
    # Login into the server and create a session
    try:
        REDFISH_OBJ.login(auth="session")
    except:
        result = {'ret': False, 'msg': "Please check the username, password, IP is correct"}
        return result
    # GET the ComputerSystem resource
    system = utils.get_system_url("/redfish/v1", REDFISH_OBJ)
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
            response_log_url = REDFISH_OBJ.get(log_url, None)
            if "Actions" in response_log_url.dict:
                if "#LogService.ClearLog" in response_log_url.dict["Actions"]:
                    clear_log_url = response_log_url.dict["Actions"]["#LogService.ClearLog"]["target"]
                    response_clear_log = REDFISH_OBJ.post(clear_log_url, None)
                    if response_clear_log.status == 200:
                        result = {'ret': True, 'msg': "Clear log successfully"}
                    else:
                    	result = {'ret': False, 'msg': "response clear log Error code %s" % response_clear_log.status}
         

        REDFISH_OBJ.logout()
        return result


if __name__ == '__main__':
    # ip = '10.10.10.10'
    # login_account = 'USERID'
    # login_password = 'PASSW0RD'
    ip = sys.argv[1]
    login_account = sys.argv[2]
    login_password = sys.argv[3]
    result = clear_system_log(ip, login_account, login_password)
    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['msg'], sort_keys=True, indent=2))
    else:
        sys.stderr.write(result['msg'])