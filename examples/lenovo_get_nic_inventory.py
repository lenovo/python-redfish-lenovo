###
#
# Lenovo Redfish examples - Get the NIC information
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


def get_nic_inventory(ip, login_account, login_password):
    result = {}
    nic_details = []
    login_host = "https://"+ip
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
        # Get the ComputerEthernetInterfaces resource
        if response_system_url.status == 200:
            processors_url = response_system_url.dict['EthernetInterfaces']['@odata.id']
        else: 
            result = {'ret': False, 'msg': "response system url Error code %s" % response_system_url.status}
            REDFISH_OBJ.logout()
            return result
        response_processors_url = REDFISH_OBJ.get(processors_url, None)
        # Get Members_url
        if response_processors_url.status == 200:
            members_count = response_processors_url.dict['Members@odata.count']
        else:
            result = {'ret': False, 'msg': "response processors url Error code %s" % response_processors_url.status}
            REDFISH_OBJ.logout()
            return result

        for i in range(members_count):
            nic = {}
            members_url = response_processors_url.dict['Members'][i]['@odata.id']

            response_members_url = REDFISH_OBJ.get(members_url, None)
            if response_members_url.status == 200:
                Id = response_members_url.dict['Id']
                name = response_members_url.dict['Name']
                description = response_members_url.dict['Description']
                odata_type = response_members_url.dict['@odata.type']
                odata_id = response_members_url.dict['@odata.id']
                permanentMACAddress = response_members_url.dict['PermanentMACAddress']
                odata_etag = response_members_url.dict['@odata.etag']
                odata_context = response_members_url.dict['@odata.context']

                nic['Id'] = Id
                nic['Name'] = name
                nic['@odata.id'] = odata_id
                nic['@odata.type'] = odata_type
                nic['PermanentMACAddress'] = permanentMACAddress
                nic['Description'] =description
                nic['@odata.etag'] = odata_etag
                nic['@odata.context'] = odata_context
                nic_details.append(nic)
            else:
                result = {'ret': False, 'msg': "response members url Error code %s" % response_members_url.status}
                REDFISH_OBJ.logout()
                return result
    
    result['ret'] = True        
    result["entries"] = nic_details
    REDFISH_OBJ.logout()
    return result


if __name__ == '__main__':
    # ip = '10.10.10.10'
    # login_account = 'USERID'
    # login_password = 'PASSW0RD'
    
    ip = sys.argv[1]
    login_account = sys.argv[2]
    login_password = sys.argv[3]
    
    result = get_nic_inventory(ip, login_account, login_password)
    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['entries'], sort_keys=True, indent=2))
    else:
        sys.stderr.write(result['msg'])