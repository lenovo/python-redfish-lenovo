###
#
# Lenovo Redfish examples - Get the CPU information
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
    REDFISH_OBJ = redfish.redfish_client(base_url=login_host, username=login_account,
                                         password=login_password, default_prefix='/redfish/v1')

    # Login into the server and create a session
    try:
        REDFISH_OBJ.login(auth="session")
    except:
        sys.stdout.write("Please check the username, password, IP is correct\n")
        sys.exit(1)
    return REDFISH_OBJ


def get_members_info(REDFISH_OBJ):
    result = {}
    cpu_details = []
    # GET the ComputerSystem resource
    system_url = utils.get_system_url("/redfish/v1", REDFISH_OBJ)
    response_system_url = REDFISH_OBJ.get(system_url, None)
    if response_system_url.status == 200:
        # Get the ComputerProcessors resource
        processors_url = response_system_url.dict['Processors']['@odata.id']
    else:
        print("response_system_url Error code %s" % response_system_url.status)
        return
    response_processors_url = REDFISH_OBJ.get(processors_url, None)

    if response_processors_url.status == 200:
        # Get Members_url
        members_count = response_processors_url.dict['Members@odata.count']
    else:
        print("response_processors_url Error code %s" % response_processors_url.status)
        return

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
            # odata_etag = response_members_url.dict['@odata.etag']
            # processor_architecture = response_members_url.dict['ProcessorArchitecture']
            # odata_context = response_members_url.dict['@odata.context']
            status_state = response_members_url.dict['Status']['State']
            status_Health = response_members_url.dict['Status']['Health']
            processor_type = response_members_url.dict['ProcessorType']
            # processor_id = response_members_url.dict['ProcessorId']
            # processor_id_step = processor_id['Step']
            # processor_id_vendorid = processor_id['VendorId']
            # processor_id_effectiveModel = processor_id['EffectiveModel']
            # processor_id_effectiveFamily = processor_id['EffectiveFamily']
            # processor_id_identificationRegisters = processor_id['IdentificationRegisters']
            total_cores = response_members_url.dict['TotalCores']
            # oem_lenovo = response_members_url.dict['Oem']['Lenovo']
            # ExternalBusClockSpeedMHz = oem_lenovo['ExternalBusClockSpeedMHz']
            # NumberOfEnabledCores = oem_lenovo['NumberOfEnabledCores']
            # CurrentClockSpeedMHz = oem_lenovo['CurrentClockSpeedMHz']
            odata_type = response_members_url.dict['@odata.type']
            id = response_members_url.dict['Id']
            manufacturer = response_members_url.dict['Manufacturer']
            max_speedMHz = response_members_url.dict['MaxSpeedMHz']
            model = response_members_url.dict['Model']
            socket = response_members_url.dict['Socket']

            sys.stdout.write("name            :  %s\n" % name)
            sys.stdout.write("odata_id        :  %s\n" % odata_id)
            sys.stdout.write("processor_type  :  %s\n" % processor_type)
            sys.stdout.write("instructionsset :  %s\n" % instructionsset)
            sys.stdout.write("description     :  %s\n" % description)
            sys.stdout.write("total_threads   :  %s\n" % total_threads)
            sys.stdout.write("status_Health   :  %s\n" % status_Health)
            sys.stdout.write("odata_type      :  %s\n" % odata_type)
            sys.stdout.write("id              :  %s\n" % id )
            sys.stdout.write("manufacturer    :  %s\n" % manufacturer)
            sys.stdout.write("max_speedMHz    :  %s\n" % max_speedMHz)
            sys.stdout.write("model           :  %s\n" % model)
            sys.stdout.write("socket          :  %s\n" % socket)
            sys.stdout.write("============================================\n" )

            cpu['name'] = name,
            cpu['manufacturer'] = manufacturer
            cpu['model'] = model
            cpu['max_speedMHz'] = max_speedMHz
            cpu['total_cores'] = total_cores
            cpu['state'] = status_state
            cpu['health'] = status_Health
            cpu_details.append(cpu)
        else:
            result = {'ret': False, 'msg': "response_members_url Error code %s" % response_members_url.status}
            REDFISH_OBJ.logout()
            return result

    result['entries'] = cpu_details
    # Logout of the current session
    REDFISH_OBJ.logout()
    return result


if __name__ == '__main__':
    login_host = 'https://' + sys.argv[1]
    login_account = sys.argv[2]
    login_password = sys.argv[3]
    REDFISH_OBJ = connect_redfish_client(login_host, login_account, login_password)
    get_members_info(REDFISH_OBJ)
