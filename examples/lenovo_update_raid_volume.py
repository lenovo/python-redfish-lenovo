###
#
# Lenovo Redfish examples - Update raid volume
#
# Copyright Notice:
#
# Copyright 2019 Lenovo Corporation
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


def update_raid_volume(ip, login_account, login_password, system_id, raidid, volume_name, read_policy, write_policy, io_policy, access_policy, drive_cache_policy):
    """Update raid volume 
    :params ip: BMC IP address
    :type ip: string
    :params login_account: BMC user name
    :type login_account: string
    :params login_password: BMC user password
    :type login_password: string
    :params system_id: ComputerSystem instance id(None: first instance, All: all instances)
    :type system_id: None or string
    :params raidid: storage id
    :type raidid: string
    :params volume_name: name of the volume
    :type volume_name: string
    :params read_policy: read policy of the volume
    :type read_policy: string
    :params write_policy: write policy of the volume
    :type write_policy: string
    :params io_policy: io policy of the volume
    :type io_policy: string
    :params access_policy: access policy of the volume
    :type access_policy: string
    :params drive_cache_policy: drive cache policy of the volume
    :type drive_cache_policy: string
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

    target_raid_volumes_url = None
    for i in range(len(system)):
        system_url = system[i]
        response_system_url = REDFISH_OBJ.get(system_url, None)
        if response_system_url.status != 200:
            result = {'ret': False, 'msg': "response_system_url Error code %s" % response_system_url.status}
            REDFISH_OBJ.logout()
            return result

        if "Storage" not in response_system_url.dict:
            continue #skip the invalid ComputeSystem that has no storage resource

        # GET the Storage resources from the ComputerSystem resource
        storage_url = response_system_url.dict["Storage"]["@odata.id"]
        response_storage_url = REDFISH_OBJ.get(storage_url, None)
        if response_storage_url.status != 200:
            result = {'ret': False, 'msg': "response storage url Error code %s" % response_storage_url.status}
            REDFISH_OBJ.logout()

        storage_count = response_storage_url.dict["Members@odata.count"]
        if storage_count == 0:
            continue #skip the invalid ComputeSystem that has no storage resource

        # Collect all storage info first
        list_raid_id = []
        list_raid_volume_names = []
        list_raid_volume_urls = []
        for raid_index in range(0, storage_count):
            storage_x_url = response_storage_url.dict["Members"][raid_index]["@odata.id"]
            response_storage_x_url = REDFISH_OBJ.get(storage_x_url, None)
            if response_storage_x_url.status != 200:
                result = {'ret': False, 'msg': "response_storage_x_url code %s" % response_storage_x_url.status}
                REDFISH_OBJ.logout()
                return result

            Storage_id = response_storage_x_url.dict["Id"]
            Name = response_storage_x_url.dict["Name"]
            list_raid_id.append(Storage_id)

            if (raidid is not None):
                if (raidid != Storage_id) and (raidid != Name):
                    continue # skip if not match
 
            volumes_url = response_storage_x_url.dict["Volumes"]["@odata.id"]
            response_volumes_url = REDFISH_OBJ.get(volumes_url, None)
            if response_volumes_url.status != 200:
                error_message = utils.get_extended_error(response_volumes_url)
                result = {'ret': False,
                          'msg': "Url '%s' response Error code %s\nerror_message: %s" % (
                              volumes_url, response_volumes_url.status,
                              error_message)}
                return result

            volume_num = len(response_volumes_url.dict["Members"])
            for volume_index in range(0, volume_num):
                volume_url = response_volumes_url.dict["Members"][volume_index]["@odata.id"]
                response_volume_url = REDFISH_OBJ.get(volume_url, None)
                if response_volume_url.status != 200:
                    result = {'ret': False, 'msg': "response_volume_url code %s" % response_volume_url.status}
                    REDFISH_OBJ.logout()
                    return result
                list_raid_volume_names.append(response_volume_url.dict["Name"])
                list_raid_volume_urls.append(volume_url)

        # Check collected info
        if len(list_raid_volume_names) == 1:
            target_raid_volumes_url = list_raid_volume_urls[0]
        elif len(list_raid_volume_names) > 1:
            for index in range(0, len(list_raid_volume_names)):
                if volume_name == list_raid_volume_names[index]:
                    if target_raid_volumes_url is None:
                        target_raid_volumes_url = list_raid_volume_urls[index]
                    else:
                        result = {'ret': False, 'msg': "There are multi-volume which can be configured. Please specified the raidid. raidid list: %s" %(str(list_raid_id))}
                        REDFISH_OBJ.logout()
                        return result

        if target_raid_volumes_url is None:
            result = {'ret': False, 'msg': "Failed to found volume that can be configured"}
            REDFISH_OBJ.logout()
            return result

        # USE PATCH to update a volume
        headers = {"Content-Type": "application/json"}
        parameter = { 
             "Name":volume_name,
             "Oem":{"Lenovo":{}}
            }
        if read_policy is not None:
            parameter["Oem"]["Lenovo"]["ReadPolicy"] = read_policy
        if write_policy is not None:
            parameter["Oem"]["Lenovo"]["WritePolicy"] = write_policy
        if io_policy is not None:
            parameter["Oem"]["Lenovo"]["IOPolicy"] = io_policy
        if access_policy is not None:
            parameter["Oem"]["Lenovo"]["AccessPolicy"] = access_policy
        if drive_cache_policy is not None:
            parameter["Oem"]["Lenovo"]["DriveCachePolicy"] = drive_cache_policy

        response_update_volume = REDFISH_OBJ.patch(target_raid_volumes_url,body=parameter, headers=headers)
        if response_update_volume.status in [200, 204]:
            result = {"ret":True,"msg":"Update volume successfully"}
            REDFISH_OBJ.logout()
            return result
        else:
            error_message = utils.get_extended_error(response_update_volume)
            result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % (
                target_raid_volumes_url, response_update_volume.status, error_message)}
            REDFISH_OBJ.logout()
            return result

    if target_raid_volumes_url is None:
        result = {'ret': False, 'msg': "Failed to found storage that can be configured"}

    # Logout of the current session
    REDFISH_OBJ.logout()
    return result


def add_helpmessage(argget):
    argget.add_argument('--raidid', type=str, required=False,
                        help="Specify the storage id when multi storage exist")
    argget.add_argument('--name', type=str, required=True,
                        help="virtual drive(VD)'s name")
    argget.add_argument('--readpolicy', type=str, required=False, choices=["NoReadAhead", "ReadAhead"],
                        help="virtual drive(VD)'s read policy")
    argget.add_argument('--writepolicy', type=str, required=False, choices=["WriteThrough", "AlwaysWriteBack", "WriteBackWithBBU"],
                        help="virtual drive(VD)'s write policy")
    argget.add_argument('--iopolicy', type=str, required=False, choices=["DirectIO", "CachedIO"],
                        help="virtual drive(VD)'s io policy")
    argget.add_argument('--accesspolicy', type=str, required=False, choices=["ReadWrite", "ReadOnly", "Blocked"],
                        help="virtual drive(VD)'s access policy")
    argget.add_argument('--drivecachepolicy', type=str, required=False, choices=["Unchanged", "Enable", "Disable"],
                        help="virtual drive(VD)'s drive cache policy")

def add_parameter():
    """Add update volume parameter"""
    parameter_info = {}
    argget = utils.create_common_parameter_list(example_string='''
Example:
  "python lenovo_update_raid_volume.py -i 10.10.10.10 -u USERID -p PASSW0RD --name Volume0 --readpolicy ReadAhead --writepolicy AlwaysWriteBack"
''')
    add_helpmessage(argget)
    args = argget.parse_args()
    parameter_info = utils.parse_parameter(args)
    parameter_info["raidid"] = args.raidid
    parameter_info["name"] = args.name
    parameter_info["readpolicy"] = args.readpolicy
    parameter_info["writepolicy"] = args.writepolicy
    parameter_info["iopolicy"] = args.iopolicy
    parameter_info["accesspolicy"] = args.accesspolicy
    parameter_info["drivecachepolicy"] = args.drivecachepolicy
    return parameter_info


if __name__ == '__main__':
    # Get parameters from config.ini and/or command line
    parameter_info = add_parameter()
    
    # Get connection info from the parameters user specified
    ip = parameter_info['ip']
    login_account = parameter_info["user"]
    login_password = parameter_info["passwd"]
    system_id = parameter_info['sysid']
    
    # update raid volume and check result
    result = update_raid_volume(ip, login_account, login_password, system_id, parameter_info["raidid"], parameter_info["name"],
                                parameter_info["readpolicy"], parameter_info["writepolicy"], parameter_info["iopolicy"], 
                                parameter_info["accesspolicy"], parameter_info["drivecachepolicy"])
    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['msg'], sort_keys=True, indent=2))
    else:
        sys.stderr.write(result['msg'])
