###
#
# Lenovo Redfish examples - get user global setting
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
import redfish
import json
import lenovo_utils as utils

def lenovo_get_bmc_user_global(ip, login_account, login_password):
    """get bmc user global settings 
    :params ip: BMC IP address
    :type ip: string
    :params login_account: BMC user name
    :type login_account: string
    :params login_password: BMC user password
    :type login_password: string
    :returns: returns bmc user global setting or error message when failed
    """
    result = {}
    # Connect using the BMC address, account name, and password
    # Create a REDFISH object
    login_host = "https://" + ip
    REDFISH_OBJ = redfish.redfish_client(base_url=login_host, username=login_account,
                                         password=login_password, default_prefix='/redfish/v1')
    # Login into the server and create a session
    REDFISH_OBJ.login(auth=utils.g_AUTH)

    try:
        # Get response_base_url resource
        response_base_url = REDFISH_OBJ.get('/redfish/v1', None)

        # Get account service url
        if response_base_url.status == 200:
            account_service_url = response_base_url.dict['AccountService']['@odata.id']
        else:
            error_message = utils.get_extended_error(response_base_url)
            result = {'ret': False, 'msg': "Url '/redfish/v1' response Error code %s \nerror_message: %s" % (
            response_base_url.status, error_message)}
            return result

        # Get AccountService resource
        response_account_service_url = REDFISH_OBJ.get(account_service_url, None)
        if response_account_service_url.status != 200:
            error_message = utils.get_extended_error(response_account_service_url)
            result = {'ret': False, 'msg': "Url '%s' response Error code %s \nerror_message: %s" % (account_service_url, response_account_service_url.status, error_message)}
            return result

        # Get global setting from AccoutService resource response
        global_setting = {}
        global_setting['AccountLockoutThreshold'] = response_account_service_url.dict['AccountLockoutThreshold']
        global_setting['AccountLockoutDuration'] = response_account_service_url.dict['AccountLockoutDuration']
        for item_name in ["PasswordChangeOnNextLogin", "AuthenticationMethod",
                          "MinimumPasswordChangeIntervalHours", "PasswordExpirationPeriodDays",
                          "PasswordChangeOnFirstAccess", "MinimumPasswordReuseCycle",
                          "PasswordLength", "WebInactivitySessionTimeout", "PasswordExpirationWarningPeriod"]:
            if 'Oem' in response_account_service_url.dict and 'Lenovo' in response_account_service_url.dict['Oem']:
                if item_name in response_account_service_url.dict['Oem']['Lenovo']:
                   global_setting[item_name] = response_account_service_url.dict['Oem']['Lenovo'][item_name]

        result['ret'] = True
        result['entries'] = global_setting

    except Exception as e:
        result = {'ret':False, 'msg':"Error message %s" %e}
    finally:
        # Logout of the current session
        REDFISH_OBJ.logout()
        return result


def add_parameter():
    """Add update user password parameter"""
    argget = utils.create_common_parameter_list(description_string="This tool can be used to get BMC user global setting include password policy and web inactivity session timeout.")
    args = argget.parse_args()
    parameter_info = utils.parse_parameter(args)
    return parameter_info


if __name__ == '__main__':
    # Get parameters from config.ini and/or command line
    parameter_info = add_parameter()

    # Get connection info from the parameters user specified
    ip = parameter_info['ip']
    login_account = parameter_info["user"]
    login_password = parameter_info["passwd"]

    # Update user password result and check result   
    result = lenovo_get_bmc_user_global(ip, login_account, login_password)
    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['entries'], sort_keys=True, indent=2))
    else:
        sys.stderr.write(result['msg'])

