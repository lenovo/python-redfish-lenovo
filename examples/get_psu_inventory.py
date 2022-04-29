###
#
# Lenovo Redfish examples - Get the PSU information
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
import traceback
import lenovo_utils as utils


def get_psu_inventory(ip, login_account, login_password):
    """Get power supply unit inventory
    :params ip: BMC IP address
    :type ip: string
    :params login_account: BMC user name
    :type login_account: string
    :params login_password: BMC user password
    :type login_password: string
    :returns: returns power supply unit inventory when succeeded or error message when failed
    """
    result = {}
    psu_details = []
    login_host = 'https://' + ip
    try:
        # Connect using the BMC address, account name, and password
        # Create a REDFISH object
        REDFISH_OBJ = redfish.redfish_client(base_url=login_host, username=login_account, timeout=utils.g_timeout,
                                             password=login_password, default_prefix='/redfish/v1', cafile=utils.g_CAFILE)

        # Login into the server and create a session
        REDFISH_OBJ.login(auth=utils.g_AUTH)
    except Exception as e:
        traceback.print_exc()
        result = {'ret': False, 'msg': "Error_message: %s. Please check if username, password and IP are correct" % repr(e)}
        return result
    try:
        response_base_url = REDFISH_OBJ.get('/redfish/v1', None)
        # Get response_base_url
        if response_base_url.status == 200:
            chassis_url = response_base_url.dict['Chassis']['@odata.id']
        else:
            error_message = utils.get_extended_error(response_base_url)
            result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % (
                '/redfish/v1', response_base_url.status, error_message)}
            return result
        response_chassis_url = REDFISH_OBJ.get(chassis_url, None)
        if response_chassis_url.status == 200:
            for request in response_chassis_url.dict['Members']:
                request_url = request['@odata.id']
                response_url = REDFISH_OBJ.get(request_url, None)
                if response_url.status == 200:
                    # if chassis is not normal skip it
                    if len(response_chassis_url.dict['Members']) > 1 and ("Links" not in response_url.dict or "ComputerSystems" not in response_url.dict["Links"]):
                        continue
                    if 'PowerSubsystem' in response_url.dict:
                        # Get the powersubsystem resources
                        powersubsystem_url = response_url.dict['PowerSubsystem']['@odata.id']
                        response_powersubsystem_url = REDFISH_OBJ.get(powersubsystem_url, None)
                        if response_powersubsystem_url.status == 200:
                            if 'PowerSupplies' not in response_powersubsystem_url.dict:
                                result = {'ret': False, 'msg': "There is no PowerSupplies data in %s" % powersubsystem_url}
                                REDFISH_OBJ.logout()
                                return result
                            # Get PowerSupplies resources
                            powersupplies_url = response_powersubsystem_url.dict['PowerSupplies']['@odata.id']
                            response_powersupplies_url = REDFISH_OBJ.get(powersupplies_url, None)
                            for i in range(response_powersupplies_url.dict["Members@odata.count"]):
                                members_url = response_powersupplies_url.dict['Members'][i]['@odata.id']
                                response_members_url = REDFISH_OBJ.get(members_url, None)
                                psu = response_members_url.dict
                                for property in ["@odata.id", "@odata.context", "@odata.type", "@odata.etag"]:
                                    if property in psu:
                                        del psu[property]
                                if 'Metrics' in response_members_url.dict:
                                    # Get Metrics resources of each PSU
                                    metrics_url = response_members_url.dict['Metrics']['@odata.id']
                                    response_metrics_url = REDFISH_OBJ.get(metrics_url, None)
                                    metrics = response_metrics_url.dict
                                    for property in ["@odata.id", "@odata.context", "@odata.type", "@odata.etag"]:
                                        if property in metrics:
                                            del metrics[property]
                                    psu["Metrics"] = metrics
                                psu_details.append(psu)
                        else:
                            error_message = utils.get_extended_error(response_powersubsystem_url)
                            result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % (
                                powersubsystem_url, response_powersubsystem_url.status, error_message)}
                            return result
                    else:
                        # Get the power resources
                        power_url = response_url.dict['Power']['@odata.id']
                        response_power_url = REDFISH_OBJ.get(power_url, None)
                        if response_power_url.status == 200:
                            if 'PowerSupplies' not in response_power_url.dict:
                                result = {'ret': False, 'msg': "There is no PowerSupplies data in %s" % power_url}
                                REDFISH_OBJ.logout()
                                return result
                            power_supply_list = response_power_url.dict['PowerSupplies']
                            for PowerSupplies in power_supply_list:
                                entry = {}
                                for property in ['Name', 'SerialNumber', 'PowerOutputWatts', 'EfficiencyPercent', 'LineInputVoltage',
                                    'PartNumber', 'FirmwareVersion', 'PowerCapacityWatts', 'PowerInputWatts', 'Model',
                                    'PowerSupplyType', 'Status', 'Manufacturer', 'HotPluggable', 'LastPowerOutputWatts',
                                    'InputRanges', 'LineInputVoltageType', 'Location']:
                                    if property in PowerSupplies:
                                        entry[property] = PowerSupplies[property]
                                if 'Oem' in PowerSupplies and 'Lenovo' in PowerSupplies['Oem']:
                                    entry['Oem'] = {'Lenovo':{}}
                                    for oemprop in ['FruPartNumber', 'ManufactureDate', 'ManufacturerName']:
                                        if oemprop in PowerSupplies['Oem']['Lenovo']:
                                            entry['Oem']['Lenovo'][oemprop] = PowerSupplies['Oem']['Lenovo'][oemprop]
                                psu_details.append(entry)
                        else:
                            error_message = utils.get_extended_error(response_power_url)
                            result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % (
                                power_url, response_power_url.status, error_message)}
                            return result
                else:
                    error_message = utils.get_extended_error(response_url)
                    result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % (
                        request_url, response_url.status, error_message)}
                    return result
        else:
            error_message = utils.get_extended_error(response_chassis_url)
            result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % (
                chassis_url, response_chassis_url.status, error_message)}
            return result
        if len(psu_details) > 0:
            result['ret'] = True
            result['entry_details'] = psu_details
        else:
            result['ret'] = False
            result['entry_details'] = []
    # Logout of the current session
    except Exception as e:
        traceback.print_exc()
        result = {'ret': False, 'msg': "error_message: %s" % e}
    finally:
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

    # Get power supply unit inventory and check result
    result = get_psu_inventory(ip, login_account, login_password)
    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['entry_details'], sort_keys=True, indent=2))
    else:
        sys.stderr.write(result['msg'] + '\n')
        sys.exit(1)

