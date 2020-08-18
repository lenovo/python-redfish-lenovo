###
#
# Lenovo Redfish examples - Get the storage information
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


def get_storage_inventory(ip, login_account, login_password, system_id):
    """Get storage inventory    
    :params ip: BMC IP address
    :type ip: string
    :params login_account: BMC user name
    :type login_account: string
    :params login_password: BMC user password
    :type login_password: string
    :params system_id: ComputerSystem instance id(None: first instance, All: all instances)
    :type system_id: None or string
    :returns: returns storage inventory when succeeded or error message when failed
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
    storage_details = []
    # GET the ComputerSystem resource
    system = utils.get_system_url("/redfish/v1", system_id, REDFISH_OBJ)
    if not system:
        result = {'ret': False, 'msg': "This system id is not exist or system member is None"}
        REDFISH_OBJ.logout()
        return result
    for i in range(len(system)):
        system_url = system[i]
        response_system_url = REDFISH_OBJ.get(system_url, None)
        if response_system_url.status == 200:
            # GET the Storage resources from the ComputerSystem resource
            if "Storage" in response_system_url.dict:
                storage_url = response_system_url.dict["Storage"]["@odata.id"]
            else:
                storage_url = response_system_url.dict["SimpleStorage"]["@odata.id"]
            response_storage_url = REDFISH_OBJ.get(storage_url, None)
            if response_storage_url.status == 200:
                storage_count = len(response_storage_url.dict["Members"])
                storage = 0
                for nic in range(0, storage_count):
                    storage_x_url = response_storage_url.dict["Members"][nic]["@odata.id"]
                    response_storage_x_url = REDFISH_OBJ.get(storage_x_url, None)
                    if response_storage_x_url.status == 200:
                        storage = {}
                        Storage_id = response_storage_x_url.dict["Id"]
                        Name = response_storage_x_url.dict["Name"]
                        storage['Id'] = Storage_id
                        storage['Name'] = Name

                        # Get the disk inventory from each of the disk resources
                        drive_list = []
                        if "Drives" in response_storage_x_url.dict:
                            for disk in response_storage_x_url.dict["Drives"]:
                                disk_inventory = {}
                                disk_url = disk["@odata.id"]
                                response_disk_url = REDFISH_OBJ.get(disk_url, None)
                                if response_disk_url.status == 200:
                                    for key in response_disk_url.dict:
                                        if key not in ["Description", "@odata.context", "@odata.id", "@odata.type",
                                                       "@odata.etag", "Links", "Actions", "RelatedItem"]:
                                            disk_inventory[key] = response_disk_url.dict[key]
                                    drive_list.append(disk_inventory)
                                else:
                                    error_message = utils.get_extended_error(response_disk_url)
                                    result = {'ret': False,
                                              'msg': "Url '%s' response Error code %s\nerror_message: %s" % (
                                                  disk_url, response_disk_url.status,
                                                  error_message)}
                                    return result
                        storage['Drives'] = drive_list

                        if "Volumes" in response_storage_x_url.dict:
                            volumes_url = response_storage_x_url.dict["Volumes"]["@odata.id"]
                            response_volumes_url = REDFISH_OBJ.get(volumes_url, None)
                            if response_volumes_url.status == 200:
                                volumes_list = []
                                for volume in response_volumes_url.dict["Members"]:
                                    volume_inventory = {}
                                    volume_url = volume["@odata.id"]
                                    response_volume_url = REDFISH_OBJ.get(volume_url, None)
                                    if response_volume_url.status == 200:
                                        for key in response_volume_url.dict:
                                            if key not in ["Description", "@odata.context", "@odata.id", "@odata.type",
                                                           "@odata.etag", "Links", "Actions", "RelatedItem"]:
                                                volume_inventory[key] = response_volume_url.dict[key]
                                        volumes_list.append(volume_inventory)
                                    else:
                                        error_message = utils.get_extended_error(response_volume_url)
                                        result = {'ret': False,
                                                  'msg': "Url '%s' response Error code %s\nerror_message: %s" % (
                                                      volume_inventory, response_volume_url.status,
                                                      error_message)}
                                        return result
                            else:
                                error_message = utils.get_extended_error(response_volumes_url)
                                result = {'ret': False,
                                          'msg': "Url '%s' response Error code %s\nerror_message: %s" % (
                                              volumes_url, response_volumes_url.status,
                                              error_message)}
                                return result
                        storage['Volumes'] = volumes_list

                        controller_count = response_storage_x_url.dict["StorageControllers@odata.count"]
                        # GET the StorageControllers instances resources from each of the Storage resources
                        storage_list = []
                        for controller in range(0, controller_count):
                            storage_controller = {}
                            for key in response_storage_x_url.dict["StorageControllers"][controller]:
                                if key not in ["Description", "@odata.context", "@odata.id", "@odata.type",
                                               "@odata.etag", "Links", "Actions", "RelatedItem"]:
                                    storage_controller[key] = response_storage_x_url.dict["StorageControllers"][controller][key]
                            storage_list.append(storage_controller)
                        storage['storage_controller'] = storage_list
                        storage_details.append(storage)
                    else:
                        result = {'ret': False, 'msg': "response_storage_x_url code %s" % response_storage_x_url.status}
                        REDFISH_OBJ.logout()
                        return result
            else:
                result = {'ret': False, 'msg': "response storage url Error code %s" % response_storage_url.status}
                REDFISH_OBJ.logout()

        else:
            result = {'ret': False, 'msg': "response_system_url Error code %s" % response_system_url.status}
            REDFISH_OBJ.logout()
            return result

    result['ret'] = True
    result['entries'] = storage_details
    # Logout of the current session
    try:
        REDFISH_OBJ.logout()
    except:
        pass
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
    
    # Get storage inventory and check result
    result = get_storage_inventory(ip, login_account, login_password, system_id)
    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['entries'], sort_keys=True, indent=2))
    else:
        sys.stderr.write(result['msg'] + '\n')
