###
#
# Lenovo Redfish examples - Get power redundancy
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

def get_power_redundancy(ip, login_account, login_password):
    """Get power redundancy
        :params ip: BMC IP address
        :type ip: string
        :params login_account: BMC user name
        :type login_account: string
        :params login_password: BMC user password
        :type login_password: string
        :returns: returns Get power redundant result when succeeded or error message when failed
        """

    result = {}
    login_host = "https://" + ip

    # Connect using the BMC address, account name, and password
    # Create a REDFISH object
    REDFISH_OBJ = redfish.redfish_client(base_url=login_host, username=login_account,
                                         password=login_password, default_prefix='/redfish/v1', cafile=utils.g_CAFILE)

    # Login into the server and create a session
    try:
        REDFISH_OBJ.login(auth=utils.g_AUTH)
    except:
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
            rt_list_redundant = []
            #Get power redundant
            for request in response_chassis_url.dict['Members']:
                request_url = request['@odata.id']
                response_url = REDFISH_OBJ.get(request_url, None)
                if response_url.status == 200:
                    # if chassis is not normal skip it
                    if len(response_chassis_url.dict['Members']) > 1 and ("Links" not in response_url.dict or
                            "ComputerSystems" not in response_url.dict["Links"]):
                        continue
                    # if no Power property, skip it
                    if "Power" not in response_url.dict:
                        continue
                    power_url = response_url.dict["Power"]['@odata.id']
                    response_power_url = REDFISH_OBJ.get(power_url, None)
                    if response_power_url.status == 200:
                        # if no Redundancy property, skip it
                        if "Redundancy" not in response_power_url.dict:
                            continue
                        list_power_redundancy = response_power_url.dict["Redundancy"]
                        for redundancy_item in list_power_redundancy:
                            dict_power_redundant = {}
                            for key in redundancy_item:
                                if key == "RedundancySet":
                                    continue
                                if key not in ["Description", "@odata.context", "@odata.id", "@odata.type",
                                               "@odata.etag", "Links", "Actions", "RelatedItem"]:
                                    dict_power_redundant[key] = redundancy_item[key]
                            rt_list_redundant.append(dict_power_redundant)
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
            if len(rt_list_redundant) > 0:
                result["ret"] = True
                result["entries"] = rt_list_redundant
            else:
                result = {'ret': False, 'msg': "No Redundancy found"}
            return result
        else:
            error_message = utils.get_extended_error(response_chassis_url)
            result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % (
                chassis_url, response_chassis_url.status, error_message)}
            return result
    except Exception as e:
        result = {'ret': False, 'msg': 'exception msg %s' % e}
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

    # Get power redundant and check result
    result = get_power_redundancy(ip, login_account, login_password)
    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['entries'], sort_keys=True, indent=2))
    else:
        sys.stderr.write(result['msg'])
