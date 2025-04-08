###
#
# Lenovo Redfish examples - Create raid volume
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
import traceback
import lenovo_utils as utils


def lenovo_create_raid_volume(ip, login_account, login_password, system_id, raidid, volume_name, raid_type, volume_capacity, read_policy, write_policy, io_policy, access_policy, drive_cache_policy, strip_size_bytes, drive_list):
    """Create raid volume 
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
    :params raid_type: raid type of the volume
    :type raid_type: string
    :params volume_capacity: capacity byte of the volume
    :type volume_capacity: int
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
    :params strip_size_bytes: strip size bytes of the volume
    :type strip_size_bytes: int
    :params drive_list: drive list of the volume
    :type drive_list: string
    :returns: returns storage inventory when succeeded or error message when failed
    """
    result = {}
    login_host = "https://" + ip
    try:
        # Connect using the BMC address, account name, and password
        # Create a REDFISH object
        REDFISH_OBJ = redfish.redfish_client(base_url=login_host, username=login_account, timeout=utils.g_timeout,
                                             password=login_password, default_prefix='/redfish/v1', cafile=utils.g_CAFILE)
        # Login into the server and create a session
        REDFISH_OBJ.login(auth=utils.g_AUTH)
    except:
        traceback.print_exc()
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

        flag_sr645_sr665 = False
        if 'SR645' in response_system_url.dict['Model'] or 'SR665' in response_system_url.dict['Model']:
            flag_sr645_sr665 = True

        # GET the Storage resources from the ComputerSystem resource
        storage_url = response_system_url.dict["Storage"]["@odata.id"]
        response_storage_url = REDFISH_OBJ.get(storage_url, None)
        if response_storage_url.status != 200:
            result = {'ret': False, 'msg': "response storage url Error code %s" % response_storage_url.status}
            REDFISH_OBJ.logout()
            return result

        storage_count = response_storage_url.dict["Members@odata.count"]
        if storage_count == 0:
            continue #skip the invalid ComputeSystem that has no storage resource

        # Collect all storage info first
        list_raid_id = []
        list_raid_name = []
        list_raid_drive_num = []
        list_raid_volume_num = []
        list_raid_volume_urls = []
        list_raid_storagePools_urls = []
        list_raid_drive_urls = []
        support_drive_slots = []
        available_storage_pools_url = []
        for raid_index in range(0, storage_count):
            storage_x_url = response_storage_url.dict["Members"][raid_index]["@odata.id"]
            response_storage_x_url = REDFISH_OBJ.get(storage_x_url, None)
            if response_storage_x_url.status != 200:
                result = {'ret': False, 'msg': "response_storage_x_url code %s" % response_storage_x_url.status}
                REDFISH_OBJ.logout()
                return result

            Storage_id = response_storage_x_url.dict["Id"]
            Name = response_storage_x_url.dict["Name"]
            drive_num = len(response_storage_x_url.dict["Drives"])
            volumes_url = response_storage_x_url.dict["Volumes"]["@odata.id"]
            storagePools_url = response_storage_x_url.dict["StoragePools"]["@odata.id"]

            for drive in response_storage_x_url.dict["Drives"]:
                if "/" in drive["@odata.id"]:
                    drive_slotname = drive["@odata.id"].split("/")[-1]
                    if "_" in drive_slotname:
                        drive_slot = drive_slotname.split("_")[-1]
                        support_drive_slots.append(drive_slot)
                    elif "." in drive_slotname:
                        drive_slot = drive_slotname.split(".")[-1]
                        support_drive_slots.append(drive_slot)
            list_raid_drive_urls.extend(response_storage_x_url.dict["Drives"])

            response_volumes_url = REDFISH_OBJ.get(volumes_url, None)
            if response_volumes_url.status != 200:
                error_message = utils.get_extended_error(response_volumes_url)
                result = {'ret': False,
                          'msg': "Url '%s' response Error code %s\nerror_message: %s" % (
                              volumes_url, response_volumes_url.status,
                              error_message)}
                return result
            volume_num = len(response_volumes_url.dict["Members"])

            list_raid_id.append(Storage_id)
            list_raid_name.append(Name)
            list_raid_drive_num.append(drive_num)
            list_raid_volume_num.append(volume_num)
            list_raid_volume_urls.append(volumes_url)
            list_raid_storagePools_urls.append(storagePools_url)

        # Found the target storage when raidid is specified
        if raidid is not None:
            for raid_index in range(0, storage_count):
                if raidid == list_raid_id[raid_index] or raidid == list_raid_name[raid_index]:
                    if list_raid_drive_num[raid_index] == 0:
                        result = {'ret': False, 'msg': "There is no Drives on specified storage %s" %(raidid)}
                        REDFISH_OBJ.logout()
                        return result
                    if list_raid_volume_num[raid_index] != 0:
                        # Check whether there are free capacity when volume has already been created
                        check_result = check_free_capacity(list_raid_storagePools_urls, raid_index, volume_capacity, drive_list, REDFISH_OBJ)
                        
                        if check_result['ret'] is True:
                            del check_result['ret']
                            if "available_storagepools_url" in check_result:
                                available_storage_pools_url = check_result['available_storagepools_url']
                        else:
                            sys.stderr.write(check_result['msg'] + '\n')
                            sys.exit(1)
                        
                    target_raid_volumes_url = list_raid_volume_urls[raid_index]
                    break
        # Check whether only one raid storage can be configured when raidid is not specified. If multi-raid can be configured, raidid need to be specified
        else:
            for raid_index in range(0, storage_count):
                if list_raid_drive_num[raid_index] == 0:
                    continue
                if list_raid_volume_num[raid_index] != 0:
                    check_result = check_free_capacity(list_raid_storagePools_urls, raid_index, volume_capacity, drive_list, REDFISH_OBJ)
                    if check_result['ret'] is True:
                        del check_result['ret']
                        if "available_storagepools_url" in check_result:
                            available_storage_pools_url = check_result['available_storagepools_url']
                    else:
                        sys.stderr.write(check_result['msg'] + '\n')
                        sys.exit(1)
                if target_raid_volumes_url is None:
                    target_raid_volumes_url = list_raid_volume_urls[raid_index]
                else:
                    result = {'ret': False, 'msg': "There are multi-storage which can be configured. Please specified the raidid. raidid list: %s" %(str(list_raid_id))}
                    REDFISH_OBJ.logout()
                    return result

        if target_raid_volumes_url is None:
            result = {'ret': False, 'msg': "Failed to found storage that can be configured"}
            REDFISH_OBJ.logout()
            return result

        # USE POST to create a volume
        headers = {"Content-Type": "application/json"}
        parameter = { 
             "Name":volume_name,
             "RAIDType":raid_type,
             "Oem":{"Lenovo":{}}
            }
        if strip_size_bytes is not None:
            parameter["StripSizeBytes"] = strip_size_bytes
        if volume_capacity > 0:
            parameter["CapacityBytes"] = volume_capacity # if you want to use all space, no need to specify CapacityBytes
        if read_policy is not None:
            if not flag_sr645_sr665:
                parameter["Oem"]["Lenovo"]["ReadPolicy"] = read_policy
            else:
                read_policy_mapdict = {
                    "NoReadAhead": "Off",
                    "ReadAhead": "ReadAhead"
                    }
                parameter["ReadCachePolicy"] = read_policy_mapdict[read_policy]
        if write_policy is not None:
            if not flag_sr645_sr665:
                parameter["Oem"]["Lenovo"]["WritePolicy"] = write_policy
            else:
                write_policy_mapdict = {
                    "WriteThrough": "WriteThrough",
                    "AlwaysWriteBack": "UnprotectedWriteBack",
                    "WriteBackWithBBU": "ProtectedWriteBack"
                    }
                parameter["WriteCachePolicy"] = write_policy_mapdict[write_policy]
        if io_policy is not None:
            parameter["Oem"]["Lenovo"]["IOPolicy"] = io_policy
        if access_policy is not None:
            parameter["Oem"]["Lenovo"]["AccessPolicy"] = access_policy
        if drive_cache_policy is not None:
            parameter["Oem"]["Lenovo"]["DriveCachePolicy"] = drive_cache_policy

        if drive_list is not None:
            drive_urls = []
            for drive_slot in drive_list:
                if drive_slot in support_drive_slots:
                    drive_urls.append(list_raid_drive_urls[support_drive_slots.index(drive_slot)])
            parameter["Links"] = {}
            parameter["Links"]["Drives"] = []
            parameter["Links"]["Drives"] = drive_urls

        if len(available_storage_pools_url) == 0:
            result = post_volume(REDFISH_OBJ, target_raid_volumes_url, login_host, parameter, headers, )
        else:
            for storage_pool_url in available_storage_pools_url:
                parameter["Oem"]["Lenovo"]["StoragePool"] = []
                parameter["Oem"]["Lenovo"]["StoragePool"].append({"@odata.id":storage_pool_url})   
                result = post_volume(REDFISH_OBJ, target_raid_volumes_url, login_host, parameter, headers)                
                if result['ret'] is True:
                    break           

    if target_raid_volumes_url is None:
        result = {'ret': False, 'msg': "Failed to found storage that can be configured"}

    # Logout of the current session
    REDFISH_OBJ.logout()
    return result

def post_volume(REDFISH_OBJ, target_raid_volumes_url, login_host, body, headers):
    response_create_volume = REDFISH_OBJ.post(target_raid_volumes_url,body=body, headers=headers)
    if response_create_volume.status in [200, 201, 204]:
        try:
            rt_link = login_host + "/" + response_create_volume.dict["@odata.id"]
            id = rt_link.split("/")[-1]
            result = {"ret":True,"msg":"Create volume successfully, volume id is " + id + ", volume 's link is:" + rt_link}
        except:
            result = {"ret":True,"msg":"Create volume successfully"}
        try:
            REDFISH_OBJ.logout()
        except:
            pass       
    else:
        error_message = utils.get_extended_error(response_create_volume)
        if "Links/Drives is a required property" in error_message:
            result = {'ret': False, 'msg': "Please specify --drivelist,  it is a required property for this machine."}
        else:
            result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % (
            target_raid_volumes_url, response_create_volume.status, error_message)}
    return result

def check_free_capacity(list_raid_storagePools_urls, raid_index, volume_capacity, drive_list, REDFISH_OBJ):
    storagepools_url = list_raid_storagePools_urls[raid_index]
    available_storagepools_url = []
    response_pools_url = REDFISH_OBJ.get(storagepools_url, None)
    if response_pools_url.status != 200:
        error_message = utils.get_extended_error(response_pools_url)
        result = {'ret': False,
                'msg': "Url '%s' response Error code %s\nerror_message: %s" % (
                    storagepools_url, response_pools_url.status,
                    error_message)}
        return result
    
    providing_drives_slots = []
    storagepool_count = response_pools_url.dict["Members@odata.count"]
    for pool_index in range(0, storagepool_count):
        storagepool_x_url = response_pools_url.dict["Members"][pool_index]["@odata.id"]
        response_storagepool_x_url = REDFISH_OBJ.get(storagepool_x_url, None)
        if response_storagepool_x_url.status != 200:
            result = {'ret': False, 'msg': "response_storagepool_x_url code %s" % response_storagepool_x_url.status}
            REDFISH_OBJ.logout()
            return result
        if drive_list is not None:
            if "CapacitySources" in response_storagepool_x_url.dict and "CapacitySources@odata.count" in response_storagepool_x_url.dict:
                capacitysource_count = response_storagepool_x_url.dict["CapacitySources@odata.count"]
                for capacity_index in range(0, capacitysource_count):
                    if "ProvidingDrives" in response_storagepool_x_url.dict["CapacitySources"][capacity_index]:
                        capacitysource_x_url = response_storagepool_x_url.dict["CapacitySources"][capacity_index]["ProvidingDrives"]["@odata.id"]
                        response_capacitysource_x_url = REDFISH_OBJ.get(capacitysource_x_url, None)
                        if response_capacitysource_x_url.status != 200:
                            result = {'ret': False, 'msg': "response_capacitysource_x_url code %s" % response_capacitysource_x_url.status}
                            REDFISH_OBJ.logout()
                            return result
                        if "Members" in response_capacitysource_x_url.dict:
                            for drive_index in range(0, len(response_capacitysource_x_url.dict["Members"])):
                                drive = response_capacitysource_x_url.dict["Members"][drive_index]
                                if "/" in drive["@odata.id"]:
                                    drive_slotname = drive["@odata.id"].split("/")[-1]
                                    if "_" in drive_slotname:
                                        drive_slot = drive_slotname.split("_")[-1]
                                        providing_drives_slots.append(drive_slot)
                                    elif "." in drive_slotname:
                                        drive_slot = drive_slotname.split(".")[-1]
                                        providing_drives_slots.append(drive_slot)
                        
                            if set(providing_drives_slots) == set(drive_list):
                                result = {'ret': False,'msg': "There is no need to specify drivelist when there is storagepool on specified the drivelist. Drive list: %s" %(str(drive_list))}       
                                REDFISH_OBJ.logout()
                            else:
                                result = {'ret': True, 'create_new_pool': True} 
                            return result                           
        
        if "Capacity" in response_storagepool_x_url.dict and "Data" in response_storagepool_x_url.dict["Capacity"] and "ConsumedBytes" in response_storagepool_x_url.dict["Capacity"]["Data"] and "AllocatedBytes" in response_storagepool_x_url.dict["Capacity"]["Data"]:
            if response_storagepool_x_url.dict["Capacity"]["Data"]["AllocatedBytes"] > response_storagepool_x_url.dict["Capacity"]["Data"]["ConsumedBytes"]:
                if response_storagepool_x_url.dict["Capacity"]["Data"]["AllocatedBytes"] - response_storagepool_x_url.dict["Capacity"]["Data"]["ConsumedBytes"] >= volume_capacity:
                    available_storagepools_url.append(storagepool_x_url)                                      
                    
    if len(available_storagepools_url) == 0:
        result = {'ret': False,'msg': "There is no free capacity on storage pool. Please check the storage pool. "}
        REDFISH_OBJ.logout()
        return result
   
    return {'ret': True, 'available_storagepools_url': available_storagepools_url}
def add_helpmessage(argget):
    argget.add_argument('--raidid', type=str, required=False,
                        help="Specify the storage id when multi storage exist")
    argget.add_argument('--name', type=str, required=True,
                        help="virtual drive(VD)'s name")
    argget.add_argument('--raidtype', type=str, required=True, choices=["RAID0", "RAID1", "RAID5", "RAID6", "RAID10", "RAID50", "RAID60"],
                        help="virtual drive(VD)'s raid type")
    argget.add_argument('--capacityMB', type=int, required=True,
                        help="virtual drive(VD)'s capacity Mega bytes. If you want to use all space, please specify -1")
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
    argget.add_argument('--stripsizeKB', type=int, required=False, default=256,
                        help="Specify the strip size Kilo bytes.")
    argget.add_argument('--drivelist', type=str, required=False, nargs='*',
                        help="Specify the drive slot list that used to create raid,example: 1 2.")

def add_parameter():
    """Add create volume parameter"""
    parameter_info = {}
    argget = utils.create_common_parameter_list(example_string='''
Example:
  "python lenovo_create_raid_volume.py -i 10.10.10.10 -u USERID -p PASSW0RD --name volume1 --raidtype RAID10 --capacityMB 500000"
''')
    add_helpmessage(argget)
    args = argget.parse_args()
    parameter_info = utils.parse_parameter(args)
    parameter_info["raidid"] = args.raidid
    parameter_info["name"] = args.name
    parameter_info["raidtype"] = args.raidtype
    parameter_info["capacityMB"] = args.capacityMB
    parameter_info["readpolicy"] = args.readpolicy
    parameter_info["writepolicy"] = args.writepolicy
    parameter_info["iopolicy"] = args.iopolicy
    parameter_info["accesspolicy"] = args.accesspolicy
    parameter_info["drivecachepolicy"] = args.drivecachepolicy
    parameter_info["stripsizeKB"] = args.stripsizeKB
    parameter_info["drivelist"] = args.drivelist
    return parameter_info


if __name__ == '__main__':
    # Get parameters from config.ini and/or command line
    parameter_info = add_parameter()
    
    # Get connection info from the parameters user specified
    ip = parameter_info['ip']
    login_account = parameter_info["user"]
    login_password = parameter_info["passwd"]
    system_id = parameter_info['sysid']
    
    # create raid volume and check result
    result = lenovo_create_raid_volume(ip, login_account, login_password, system_id,
                                parameter_info["raidid"], parameter_info["name"], parameter_info["raidtype"],
                                parameter_info["capacityMB"]*1024*1024 if parameter_info["capacityMB"] > 0 else -1,
                                parameter_info["readpolicy"], parameter_info["writepolicy"], parameter_info["iopolicy"],
                                parameter_info["accesspolicy"], parameter_info["drivecachepolicy"],
                                parameter_info["stripsizeKB"]*1024, parameter_info["drivelist"])
    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['msg'], sort_keys=True, indent=2) + '\n')
    else:
        sys.stderr.write(result['msg'] + '\n')
        sys.exit(1)
