###
#
# Lenovo Redfish examples - Set BMC timezone
#
# Copyright Notice:
#
# Copyright 2020 Lenovo Corporation
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


def set_bmc_timezone(ip, login_account, login_password, timezone):
    """Set BMC timezone
    :params ip: BMC IP address
    :type ip: string
    :params login_account: BMC user name
    :type login_account: string
    :params login_password: BMC user password
    :type login_password: string
    :params timezone: timezone by user specified
    :type timezone: string
    :returns: returns set BMC timezone result when succeeded or error message when failed
    """
    result = {}
    login_host = "https://" + ip

    # Connect using the BMC address, account name, and password
    # Create a REDFISH object
    REDFISH_OBJ = redfish.redfish_client(base_url=login_host, username=login_account,
                                         password=login_password, default_prefix='/redfish/v1')

    # Login into the server and create a session
    REDFISH_OBJ.login(auth=utils.g_AUTH)

    # Get ServiceBase resource
    response_base_url = REDFISH_OBJ.get('/redfish/v1', None)
    # Get response_base_url
    if response_base_url.status == 200:
        manager_url = response_base_url.dict['Managers']['@odata.id']
    else:
        error_message = utils.get_extended_error(response_base_url)
        result = {'ret': False, 'msg': "Url '/redfish/v1' response error code %s \nerror_message: %s" % (
            response_base_url.status, error_message)}
        REDFISH_OBJ.logout()
        return result

    # Get the manager url response resource
    response_manager_url = REDFISH_OBJ.get(manager_url, None)
    if response_manager_url.status != 200:
        error_message = utils.get_extended_error(response_manager_url)
        result = {'ret': False, 'msg': "Url '%s' response error code %s \nerror_message: %s" % (
            manager_url, response_manager_url.status, error_message)}
        REDFISH_OBJ.logout()
        return result
    for request in response_manager_url.dict['Members']:
        request_url = request['@odata.id']
        response_url = REDFISH_OBJ.get(request_url, None)
        if response_url.status != 200:
            error_message = utils.get_extended_error(response_url)
            result = {'ret': False, 'msg': "Url '%s' response error code %s \nerror_message: %s" % (
                request_url, response_url.status, error_message)}
            REDFISH_OBJ.logout()
            return result

        # get etag to set If-Match precondition
        if "@odata.etag" in response_url.dict:
            etag = response_url.dict['@odata.etag']
        else:
            etag = "*"
        headers = {"If-Match": etag}

        # Build patch body for request to set timezone
        payload = {"DateTimeLocalOffset":timezone}
        response_url = REDFISH_OBJ.patch(request_url, body=payload, headers=headers)
        if response_url.status in [200,204]:
            result = {'ret': True, 'msg': "Set BMC timezone successfully"}
            REDFISH_OBJ.logout()
            return result
        else:
            error_message = utils.get_extended_error(response_url)
            result = {'ret': False, 'msg': "Url '%s' response error code %s \nerror_message: %s" % (
                request_url, response_url.status, error_message)}
            REDFISH_OBJ.logout()
            return result


def add_helpmessage(argget):
    argget.add_argument('--timezone', type=str, required=True, help="Specify the time offset from UTC, format should be +HH:MM or -HH:MM, such as '+08:00', ' -05:00'. For current timezone, you can call get_bmc_inventory script and check DateTimeLocalOffset property")


def add_parameter():
    """Add set BMC timezone parameter"""
    argget = utils.create_common_parameter_list()
    add_helpmessage(argget)
    args = argget.parse_args()
    parameter_info = utils.parse_parameter(args)
    parameter_info["timezone"] = args.timezone
    return parameter_info


if __name__ == '__main__':
    # Get parameters from config.ini and/or command line
    parameter_info = add_parameter()

    # Get connection info from the parameters user specified
    ip = parameter_info['ip']
    login_account = parameter_info["user"]
    login_password = parameter_info["passwd"]
    timezone = parameter_info['timezone'].strip()

    # Set BMC timezone result and check result
    result = set_bmc_timezone(ip, login_account, login_password, timezone)
    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['msg'], sort_keys=True, indent=2))
    else:
        sys.stderr.write(result['msg'])
