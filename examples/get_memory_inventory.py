###
#
# Lenovo Redfish examples - Get memory inventory
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


def get_memory_inventory(ip, login_account, login_password, system_id, member_id):
    """Get memory inventory
    :params ip: BMC IP address
    :type ip: string
    :params login_account: BMC user name
    :type login_account: string
    :params login_password: BMC user password
    :type login_password: string
    :params system_id: ComputerSystem instance id(None: first instance, All: all instances)
    :type system_id: None or string
    :params member_id: Memory member id
    :type member_id: None or int
    :returns: returns memory inventory when succeeded or error message when failed
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

    system_details = []
    # GET the ComputerSystem resource
    try:
        system = utils.get_system_url("/redfish/v1", system_id, REDFISH_OBJ)
        if not system:
            result = {'ret': False, 'msg': "This system id is not exist or system member is None"}
            return result
        list_memory_info = []
        for i in range(len(system)):
            system_url = system[i]
            response_system_url = REDFISH_OBJ.get(system_url, None)
            if response_system_url.status == 200:
                memroys_url = response_system_url.dict["Memory"]["@odata.id"]
                response_memory_url = REDFISH_OBJ.get(memroys_url,None)
                if response_memory_url.status == 200:
                    list_memory_url = response_memory_url.dict["Members"]
                    # check member_id validity
                    if member_id != None:
                        if member_id <= 0 or member_id > len(list_memory_url):
                            result = {'ret': False, 'msg': "Specified member id is not valid. The id should be within 1~%s" % (len(list_memory_url))}
                            REDFISH_OBJ.logout()
                            return result

                    # get each memory info
                    index = 1
                    for memory_dict in list_memory_url:
                        if member_id != None and index != member_id:
                            index = index + 1
                            continue
                        index = index + 1
                        sub_memory_url = memory_dict["@odata.id"]
                        response_sub_memory_url = REDFISH_OBJ.get(sub_memory_url,None)
                        if response_sub_memory_url.status == 200:
                            memory_info = {}
                            if response_sub_memory_url.dict["Status"]["State"] == "Absent":
                                memory_info["Status"] = response_sub_memory_url.dict["Status"]
                                memory_info["MemoryLocation"] = response_sub_memory_url.dict["MemoryLocation"]
                                memory_info["Id"] = response_sub_memory_url.dict["Id"]
                                memory_info["Name"] = response_sub_memory_url.dict["Name"]
                                list_memory_info.append(memory_info)
                                continue
                            for key in response_sub_memory_url.dict:
                                if key == "Oem":
                                    continue
                                if key not in ["Description", "@odata.context", "@odata.id", "@odata.type",
                                               "@odata.etag", "Links", "Actions", "RelatedItem"]:
                                    memory_info[key] = response_sub_memory_url.dict[key]
                            list_memory_info.append(memory_info)
                        else:
                            error_message = utils.get_extended_error(response_sub_memory_url)
                            result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % (
                                sub_memory_url, response_sub_memory_url.status, error_message)}
                            return result
                else:
                    error_message = utils.get_extended_error(response_memory_url)
                    result = {'ret': False, 'msg': "Url '%s' response Error code %s\n error_message: %s" % (
                        memroys_url, response_memory_url.status, error_message)}
                    return result
            else:
                error_message = utils.get_extended_error(response_system_url)
                result = {'ret': False, 'msg': "Url '%s' response Error code %s\n error_message: %s" % (
                    system_url, response_system_url.status, error_message)}
                return result

            result['ret'] = True
            result['entries'] = list_memory_info
            return result
    except Exception as e:
        result = {'ret': False, 'msg': "exception msg %s" % e}
        return result
    finally:
        try:
            REDFISH_OBJ.logout()
        except:
            pass

import argparse
def add_parameter():
    """Add member parameter"""
    argget = utils.create_common_parameter_list()
    argget.add_argument('--member', type=int,  help="Specify the member id to get only one member from list. 1 for first member, 2 for second, etc")
    args = argget.parse_args()
    parameter_info = utils.parse_parameter(args)
    parameter_info['member'] = args.member
    return parameter_info


if __name__ == '__main__':
    # Get parameters from config.ini and/or command line
    parameter_info = add_parameter()

    # Get connection info from the parameters user specified
    ip = parameter_info['ip']
    login_account = parameter_info["user"]
    login_password = parameter_info["passwd"]
    system_id = parameter_info['sysid']
    member_id = parameter_info['member']

    # Get memory inventory and check result
    result = get_memory_inventory(ip, login_account, login_password, system_id, member_id)
    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['entries'], sort_keys=True, indent=2))
    else:
        sys.stderr.write(result['msg'])

