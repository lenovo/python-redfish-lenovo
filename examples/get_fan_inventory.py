###
#
# Lenovo Redfish examples - Get fan inventory
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

def get_fan_inventory(ip, login_account, login_password):
    """Get fan inventory
        :params ip: BMC IP address
        :type ip: string
        :params login_account: BMC user name
        :type login_account: string
        :params login_password: BMC user password
        :type login_password: string
        :returns: returns get fan inventory result when succeeded or error message when failed
        """

    result = {}
    login_host = "https://" + ip

    # Connect using the BMC address, account name, and password
    # Create a REDFISH object
    REDFISH_OBJ = redfish.redfish_client(base_url=login_host, username=login_account, timeout=utils.g_timeout,
                                         password=login_password, default_prefix='/redfish/v1', cafile=utils.g_CAFILE)

    # Login into the server and create a session
    try:
        REDFISH_OBJ.login(auth=utils.g_AUTH)
    except:
        traceback.print_exc()
        result = {'ret': False, 'msg': "Please check the username, password, IP is correct\n"}
        return result
    # Get ServiceBase resource
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
            #get Fan info
            rt_list_fan = []
            for request in response_chassis_url.dict['Members']:
                request_url = request['@odata.id']
                response_url = REDFISH_OBJ.get(request_url, None)
                if response_url.status == 200:
                    # if chassis is not normal skip it
                    try:
                        if len(response_chassis_url.dict['Members']) > 1 and ("Links" not in response_url.dict or
                                "ComputerSystems" not in response_url.dict["Links"]):
                            continue
                    except:
                        continue
                    if 'ThermalSubsystem' in response_url.dict and '@odata.id' in response_url.dict['ThermalSubsystem']:
                        thermal_url = response_url.dict['ThermalSubsystem']['@odata.id']
                        response_thermal_url = REDFISH_OBJ.get(thermal_url, None)
                        if response_thermal_url.status != 200:
                            error_message = utils.get_extended_error(response_thermal_url)
                            result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % (
                                thermal_url, response_thermal_url.status, error_message)}
                            return result
                        list_fan_url = response_thermal_url.dict["Fans"]['@odata.id']
                        list_fan_response = REDFISH_OBJ.get(list_fan_url, None)
                        if list_fan_response.status != 200:
                            error_message = utils.get_extended_error(list_fan_response)
                            result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % (
                                list_fan_url, list_fan_response.status, error_message)}
                            return result
                        for list_fans in list_fan_response.dict['Members']:
                            members_url = list_fans['@odata.id']
                            fans_members = REDFISH_OBJ.get(members_url, None)
                            if fans_members.status == 200:
                                speed_percent_url = fans_members.dict['SpeedPercent']['DataSourceUri']
                                response_speed_percent = REDFISH_OBJ.get(speed_percent_url, None)
                                tmp_fan_item = {}
                                for key in response_speed_percent.dict:
                                    if key == "Oem":
                                        continue
                                    if key not in ["Description", "@odata.context", "@odata.id", "@odata.type",
                                                   "@odata.etag", "Links", "Actions", "RelatedItem"]:
                                        tmp_fan_item[key] = response_speed_percent.dict[key]
                                rt_list_fan.append(tmp_fan_item)
                            else:
                                error_message = utils.get_extended_error(fans_members)
                                result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % (
                                    members_url, fans_members.status, error_message)}
                                return result
                    else:
                        if "Thermal" not in response_url.dict:
                            continue
                        thermal_url = response_url.dict['Thermal']['@odata.id']
                        response_thermal_url = REDFISH_OBJ.get(thermal_url, None)
                        if response_thermal_url.status == 200:
                            list_fan = response_thermal_url.dict["Fans"]
                            for fan_item in list_fan:
                                tmp_fan_item = {}
                                for key in fan_item:
                                    if key == "Oem":
                                        continue
                                    if key not in ["Description", "@odata.context", "@odata.id", "@odata.type",
                                                   "@odata.etag", "Links", "Actions", "RelatedItem"]:
                                        tmp_fan_item[key] = fan_item[key]
                                rt_list_fan.append(tmp_fan_item)
                        else:
                            error_message = utils.get_extended_error(response_thermal_url)
                            result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % (
                                thermal_url, response_thermal_url.status, error_message)}
                            return result
                else:
                    error_message = utils.get_extended_error(response_url)
                    result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % (
                        request_url, response_url.status, error_message)}
                    return result
            result["ret"] = True
            result["entries"] = rt_list_fan
            return result
        else:
            error_message = utils.get_extended_error(response_chassis_url)
            result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % (
                chassis_url, response_chassis_url.status, error_message)}
            return result
    except Exception as e:
        traceback.print_exc()
        result = {'ret': False, 'msg': "exception msg %s" % e}
        return result
    finally:
        try:
            REDFISH_OBJ.logout()
        except:
            pass


if __name__ == '__main__':
    # Get parameters from config.ini and/or command line
    argget = utils.create_common_parameter_list()
    args = argget.parse_args()
    parameter_info = utils.parse_parameter(args)

    # Get connection info from the parameters user specified
    ip = parameter_info['ip']
    login_account = parameter_info["user"]
    login_password = parameter_info["passwd"]

    # Get fan inventory and check result
    result = get_fan_inventory(ip, login_account, login_password)
    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['entries'], sort_keys=True, indent=2))
    else:
        sys.stderr.write(result['msg'])
        sys.exit(1)
