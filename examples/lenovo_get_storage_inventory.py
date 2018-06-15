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


def get_storage_info(ip, login_account, login_passwprd, system_id):
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
            storage_url = response_system_url.dict["Storage"]["@odata.id"]
            response_storage_url = REDFISH_OBJ.get(storage_url, None)
            if response_storage_url.status == 200:
                storage_count = response_storage_url.dict["Members@odata.count"]
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
                        controller_count = response_storage_x_url.dict["StorageControllers@odata.count"]
                        controller = 0
                        # GET the StorageControllers instances resources from each of the Storage resources
                        storage_list = []
                        for controller in range(0, controller_count):
                            storage_controller = {}
                            Controller = controller
                            Manufacturer = response_storage_x_url.dict["StorageControllers"][controller]["Manufacturer"]
                            Model = response_storage_x_url.dict["StorageControllers"][controller]["Model"]
                            SerialNumber = response_storage_x_url.dict["StorageControllers"][controller]["SerialNumber"]
                            FirmwareVersion = response_storage_x_url.dict["StorageControllers"][controller][
                                "FirmwareVersion"]
                            PartNumber = response_storage_x_url.dict["StorageControllers"][controller]["PartNumber"]
                            DurableNameFormat = \
                            response_storage_x_url.dict["StorageControllers"][controller]["Identifiers"][0][
                                "DurableNameFormat"]
                            DurableName = \
                            response_storage_x_url.dict["StorageControllers"][controller]["Identifiers"][0][
                                "DurableName"]
                            storage_controller[Manufacturer] = Manufacturer
                            storage_controller["Model"] = Model
                            storage_controller["SerialNumber"] = SerialNumber
                            storage_controller["FirmwareVersion"] = FirmwareVersion
                            storage_controller["PartNumber"] = PartNumber
                            storage_controller["DurableNameFormat"] = DurableNameFormat
                            storage_controller["DurableName"] = DurableName
                            storage_list.append(storage_controller)
                        storage['torage_controller'] = storage_list
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
    REDFISH_OBJ.logout()
    return result


if __name__ == '__main__':
    # ip = '10.10.10.10'
    # login_account = 'USERID'
    # login_password = 'PASSW0RD'
    ip = sys.argv[1]
    login_account = sys.argv[2]
    login_password = sys.argv[3]
    try:
        system_id = sys.argv[4]
    except IndexError:
        system_id = None
    result = get_storage_info(ip, login_account, login_password, system_id)
    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['entries'], sort_keys=True, indent=2))
    else:
        sys.stderr.write(result['msg'])