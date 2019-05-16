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


def get_cpu_info(ip, login_account, login_password, system_id):
    """Get cpu inventory    
    :params ip: BMC IP address
    :type ip: string
    :params login_account: BMC user name
    :type login_account: string
    :params login_password: BMC user password
    :type login_password: string
    :params system_id: ComputerSystem instance id(None: first instance, All: all instances)
    :type system_id: None or string
    :returns: returns cpu inventory when succeeded or error message when failed
    """
    result = {}
    login_host = "https://" + ip
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

    cpu_details = []
    # GET the ComputerSystem resource
    system = utils.get_system_url("/redfish/v1", system_id, REDFISH_OBJ)
    if not system:
        result = {'ret': False, 'msg': "This system id is not exist or system member is None"}
        REDFISH_OBJ.logout()
        return result

    for i in range(len(system)):
        # Get Processors url
        system_url = system[i]
        response_system_url = REDFISH_OBJ.get(system_url, None)
        if response_system_url.status == 200:
            processors_url = response_system_url.dict['Processors']['@odata.id']
        else:
            result = {'ret': False, 'msg': "response_system_url Error code %s" % response_system_url.status}
            REDFISH_OBJ.logout()
            return result

        # Get the Processors collection
        response_processors_url = REDFISH_OBJ.get(processors_url, None)
        if response_processors_url.status == 200:
            # Get Members url
            members_count = response_processors_url.dict['Members@odata.count']
        else:
            result = {'ret': False, 'msg': "response_processors_url Error code %s" % response_processors_url.status}
            REDFISH_OBJ.logout()
            return result

        # Get each processor info
        for i in range(members_count):
            cpu = {}
            # Get members url resource
            members_url = response_processors_url.dict['Members'][i]['@odata.id']
            response_members_url = REDFISH_OBJ.get(members_url, None)
            if response_members_url.status == 200:
                for property in ['Id', 'Name', 'TotalThreads', 'InstructionSet', 'Status', 'ProcessorType', 
                    'TotalCores', 'Manufacturer', 'MaxSpeedMHz', 'Model', 'Socket']:
                    if property in response_members_url.dict:
                        cpu[property] = response_members_url.dict[property]
                cpu_details.append(cpu)
            else:
                result = {'ret': False, 'msg': "response_members_url Error code %s" % response_members_url.status}

    result['ret'] = True
    result['entries'] = cpu_details
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
    
    # Get cpu inventory and check result
    result = get_cpu_info(ip, login_account, login_password, system_id)
    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['entries'], sort_keys=True, indent=2))
    else:
        sys.stderr.write(result['msg'])
