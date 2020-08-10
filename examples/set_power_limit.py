###
#
# Lenovo Redfish examples - Set power limit
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


def set_power_limit(ip, login_account, login_password, isenable, power_limit):
    """Set power limit
    :params ip: BMC IP address
    :type ip: string
    :params login_account: BMC user name
    :type login_account: string
    :params login_password: BMC user password
    :type login_password: string
    :params isenable: Enable/Disable power limit
    :type isenable int
    :params power_limit: Value of power limit
    :type power_limit: int
    :returns: returns Set power limit result when succeeded or error message when failed
    """
    isenable = bool(isenable)
    #check paramater
    if isenable is True and (power_limit < 1 or power_limit > 32766):
        result = {'ret':False,'msg':'Failed to set power limit, please check paramater powerlimit'}
        return result
    result = {}
    login_host = "https://" + ip

    # Connect using the BMC address, account name, and password
    # Create a REDFISH object
    REDFISH_OBJ = redfish.redfish_client(base_url=login_host, username=login_account,
                                         password=login_password, default_prefix='/redfish/v1', cafile=utils.g_CAFILE)

    # Login into the server and create a session
    try:
        REDFISH_OBJ.login(auth=utils.g_AUTH)
    except Exception as e:
        result = {'ret': False, 'msg': "Error_message: %s. Please check if username, password and IP are correct" % repr(e)}
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
            #Set power limit
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
                        # if no PowerControl property, skip it
                        if "PowerControl" not in response_power_url.dict:
                            continue
                        # get etag to set If-Match precondition
                        if "@odata.etag" in response_power_url.dict:
                            etag = response_power_url.dict['@odata.etag']
                        else:
                            etag = ""
                        headers = {"If-Match": etag}

                        list_power_control = response_power_url.dict["PowerControl"]
                        # check powerlimit existed or not
                        try:
                            limit_item = list_power_control[0]["PowerLimit"]
                        except Exception as e:
                            result = {"ret": False, "msg": "Not support this function"}
                            return result
                        if isenable is True:
                            parameter = {"PowerControl": [{"PowerLimit":{"LimitInWatts": power_limit}}]}
                        else:
                            parameter = {"PowerControl": [{"PowerLimit":{"LimitInWatts": None}}]}
                        response_limit_set_url = REDFISH_OBJ.patch(power_url, body=parameter, headers=headers)
                        if response_limit_set_url.status in [200,204]:
                            result = {"ret":True,"msg":"Set power limit successfully"}
                            return result
                        else:
                            error_message = utils.get_extended_error(response_limit_set_url)
                            result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % (
                                power_url, response_limit_set_url.status, error_message)}
                            return result
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

            result = {'ret': False, 'msg': "No PowerLimit found"}
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


def add_helpmessage(argget):
    help_str = 'It is used to set power capping enabled or disabled(0:disabled,1:enabled).'
    help_str += 'When power capping is enabled, the system may be throttled in order to maintain the power limit, you can set power limit using paramater powerlimit.'
    argget.add_argument('--isenable', type=int, help = help_str)
    help_str = 'Input the power limit you want to set (When isenable is 1, powerlimit is necessary. When isenable is 0, powerlimit is ignored).'
    help_str += 'Note: maximum power limit is 32766.'
    argget.add_argument('--powerlimit', type=int, default = 0, help = help_str)


def add_parameter():
    """Add Set power limit parameter"""
    parameter_info = {}
    argget = utils.create_common_parameter_list()
    add_helpmessage(argget)
    args = argget.parse_args()
    parameter_info = utils.parse_parameter(args)
    parameter_info["powerlimit"] = args.powerlimit
    parameter_info["isenable"] = args.isenable
    return parameter_info


if __name__ == '__main__':
    # Get parameters from config.ini and/or command line
    parameter_info = add_parameter()

    # Get connection info from the parameters user specified
    ip = parameter_info['ip']
    login_account = parameter_info["user"]
    login_password = parameter_info["passwd"]
    power_limit = parameter_info["powerlimit"]
    isenable = parameter_info["isenable"]
    # Set power limit and check result
    result = set_power_limit(ip, login_account, login_password, isenable, power_limit)
    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['msg'], sort_keys=True, indent=2))
    else:
        sys.stderr.write(result['msg'] + '\n')
