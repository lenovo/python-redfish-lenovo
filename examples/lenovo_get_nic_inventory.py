###
#
# Lenovo Redfish examples - Get the NIC information
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


def connect_redfish_client(host, userid, password):
    # Connect using the address, account name, and password
    ## Create a REDFISH object
    REDFISH_OBJ = redfish.redfish_client(base_url=host, username=userid,
                                         password=password, default_prefix='/redfish/v1')

    # Login into the server and create a session
    try:
        REDFISH_OBJ.login(auth="session")
    except:
        sys.stdout.write("Please check the username, password, IP is correct\n")
        sys.exit(1)
    return REDFISH_OBJ


def get_members_info(REDFISH_OBJ):
    result = {}
    nic_details = []
    # GET the ComputerSystem resource
    system_url = utils.get_system_url("/redfish/v1", REDFISH_OBJ)
    response_system_url = REDFISH_OBJ.get(system_url, None)

    # Get the ComputerEthernetInterfaces resource
    if response_system_url.status == 200:
        processors_url = response_system_url.dict['EthernetInterfaces']['@odata.id']
    else:
        print("response_system_url Error code %s" % response_system_url.status)
        return
    response_processors_url = REDFISH_OBJ.get(processors_url, None)
    # Get Members_url
    if response_processors_url.status == 200:
        members_count = response_processors_url.dict['Members@odata.count']
    else:
        print("response_processors_url Error code %s" % response_processors_url.status)
        return

    for i in range(members_count):
        nic = {}
        members_url = response_processors_url.dict['Members'][i]['@odata.id']

        response_members_url = REDFISH_OBJ.get(members_url, None)
        if response_members_url.status == 200:
            id = response_members_url.dict['Id']
            name = response_members_url.dict['Name']
            description = response_members_url.dict['Description']
            odata_type = response_members_url.dict['@odata.type']
            odata_id = response_members_url.dict['@odata.id']
            permanentMACAddress = response_members_url.dict['PermanentMACAddress']
            odata_etag = response_members_url.dict['@odata.etag']
            odata_context = response_members_url.dict['@odata.context']

            sys.stdout.write("id                  :  %s\n" % id)
            sys.stdout.write("name                :  %s\n" % name)
            sys.stdout.write("odata_id            :  %s\n" % odata_id)
            sys.stdout.write("odata_type          :  %s\n" % odata_type)
            sys.stdout.write("permanentMACAddress :  %s\n" % permanentMACAddress)
            sys.stdout.write("description         :  %s\n" % description)
            sys.stdout.write("odata_etag          :  %s\n" % odata_etag)
            sys.stdout.write("odata_context       :  %s\n" % odata_context)
            sys.stdout.write("======================================================\n")

            nic['name'] = name
            nic['odata_id'] = odata_id
            nic['odata_type'] = odata_type
            nic['permanentMACAddress'] = permanentMACAddress
            nic['description'] =description
            nic['odata_etag'] = odata_etag
            nic['odata_context'] = odata_context
            nic_details.append(nic)
        else:
            result = {'ret': False, 'msg': "response_members_url Error code %s" % response_members_url.status}
            return result
    result["entries"] = nic_details
    REDFISH_OBJ.logout()
    return result


if __name__ == '__main__':
    login_host = 'https://' + sys.argv[1]
    login_account = sys.argv[2]
    login_password = sys.argv[3]
    REDFISH_OBJ = connect_redfish_client(login_host, login_account, login_password)
    get_members_info(REDFISH_OBJ)