###
#
# Lenovo Redfish examples - Get the CPU information
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


def get_cpu_info(ip, login_account, login_password):
    result = {}
    # Connect using the BMC address, account name, and password
    # Create a REDFISH object
    login_host = "https://" + ip
    REDFISH_OBJ = redfish.redfish_client(base_url=login_host, username=login_account,
                                         password=login_password, default_prefix='/redfish/v1')

    # Login into the server and create a session
    try:
        REDFISH_OBJ.login(auth="session")
    except:
        result = {'ret':False, 'msg':"Please check the username, password, IP is correct"}
        return result

    
    cpu_details = []
    # GET the ComputerSystem resource
    system = utils.get_system_url("/redfish/v1", REDFISH_OBJ)
    for i in range(len(system)):
        system_url = system[i]
        response_system_url = REDFISH_OBJ.get(system_url, None)
        if response_system_url.status == 200:
            # Get the ComputerProcessors resource
            processors_url = response_system_url.dict['Processors']['@odata.id']
        else:
            result = {'ret': False, 'msg': "response_system_url Error code %s" % response_system_url.status}
            REDFISH_OBJ.logout()
            return result
        response_processors_url = REDFISH_OBJ.get(processors_url, None)

        if response_processors_url.status == 200:
            # Get Members_url
            members_count = response_processors_url.dict['Members@odata.count']
        else:
            result = {'ret': False, 'msg': "response_processors_url Error code %s" % response_processors_url.status}
            REDFISH_OBJ.logout()
            return result

        for i in range(members_count):
            cpu = {}
            members_url = response_processors_url.dict['Members'][i]['@odata.id']
            response_members_url = REDFISH_OBJ.get(members_url, None)
            if response_members_url.status == 200:
                name = response_members_url.dict['Name']
                odata_id = response_members_url.dict["@odata.id"]
                total_threads = response_members_url.dict["TotalThreads"]
                instructionsset = response_members_url.dict['InstructionSet']
                description = response_members_url.dict['Description']
                status_state = response_members_url.dict['Status']['State']
                if "Health" in response_members_url.dict:
                    status_Health = response_members_url.dict['Status']['Health']
                else:
                    status_Health = "None"
                processor_type = response_members_url.dict['ProcessorType']
                total_cores = response_members_url.dict['TotalCores']
                odata_type = response_members_url.dict['@odata.type']
                id = response_members_url.dict['Id']
                manufacturer = response_members_url.dict['Manufacturer']
                max_speedMHz = response_members_url.dict['MaxSpeedMHz']
                model = response_members_url.dict['Model']
                socket = response_members_url.dict['Socket']

                cpu['Name'] = name
                cpu['ProcessorType'] = processor_type
                cpu['InstructionSet'] = instructionsset
                cpu['Manufacturer'] = manufacturer
                cpu['Model'] = model
                cpu['MaxSpeedMHz'] = max_speedMHz
                cpu['Socket'] = socket
                cpu['TotalCores'] = total_cores
                cpu['TotalThreads'] = total_threads
                cpu['State'] = status_state
                cpu['Health'] = status_Health
                cpu_details.append(cpu)
            else:
                result = {'ret': False, 'msg': "response_members_url Error code %s" % response_members_url.status}
    
    result['ret'] = True
    result['entries'] = cpu_details
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
    result = get_cpu_info(ip, login_account, login_password)
    
    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['entries'], sort_keys=True, indent=2))
    else:
        sys.stderr.write(result['msg'])
