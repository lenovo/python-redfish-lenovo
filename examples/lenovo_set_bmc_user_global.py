###
#
# Lenovo Redfish examples - update user global setting
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

def lenovo_set_bmc_user_global(ip, login_account, login_password, setting_dict):
    """update bmc user global settings 
    :params ip: BMC IP address
    :type ip: string
    :params login_account: BMC user name
    :type login_account: string
    :params login_password: BMC user password
    :type login_password: string
    :params setting_dict: global setting for all BMC users
    :type setting_dict: string
    :returns: returns succeeded message or error message when failed
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
        global_setting['Oem'] = {}
        global_setting['Oem']['Lenovo'] = {}
        for item_name in ["PasswordChangeOnNextLogin", "AuthenticationMethod",
                          "MinimumPasswordChangeIntervalHours", "PasswordExpirationPeriodDays",
                          "PasswordChangeOnFirstAccess", "MinimumPasswordReuseCycle",
                          "PasswordLength", "WebInactivitySessionTimeout", "PasswordExpirationWarningPeriod"]:
            if 'Oem' in response_account_service_url.dict and 'Lenovo' in response_account_service_url.dict['Oem']:
                if item_name in response_account_service_url.dict['Oem']['Lenovo']:
                    global_setting['Oem']['Lenovo'][item_name] = response_account_service_url.dict['Oem']['Lenovo'][item_name]

        # Use user setting to update global_setting dict
        if "AccountLockoutThreshold" in setting_dict:
            global_setting['AccountLockoutThreshold'] = setting_dict['AccountLockoutThreshold'] 
        if "AccountLockoutDuration" in setting_dict:
            global_setting['AccountLockoutDuration'] = setting_dict['AccountLockoutDuration'] 
        for item_name in ["PasswordChangeOnNextLogin", "AuthenticationMethod",
                          "MinimumPasswordChangeIntervalHours", "PasswordExpirationPeriodDays",
                          "PasswordChangeOnFirstAccess", "MinimumPasswordReuseCycle",
                          "PasswordLength", "WebInactivitySessionTimeout", "PasswordExpirationWarningPeriod"]:
            if item_name in setting_dict:
                global_setting['Oem']['Lenovo'][item_name] = setting_dict[item_name]

        # Perform patch to change setting
        if "@odata.etag" in response_account_service_url.dict:
            etag = response_account_service_url.dict['@odata.etag']
        else:
            etag = ""
        headers = {"If-Match": etag}
        response_modified_global = REDFISH_OBJ.patch(account_service_url, body=global_setting, headers=headers)
        if response_modified_global.status in [200,204]:
            result = {'ret': True, 'msg': "The BMC user global setting is successfully updated."}
            return result
        else:
            error_message = utils.get_extended_error(response_modified_global)
            result = {'ret': False, 'msg': "Update BMC user global setting failed, url '%s' response error code %s \nerror_message: %s" % (account_service_url, response_modified_global.status, error_message)}
            return result

    except Exception as e:
        result = {'ret':False, 'msg':"Error message %s" %e}
    finally:
        # Logout of the current session
        REDFISH_OBJ.logout()
        return result


import argparse
def add_helpmessage(argget):
    argget.add_argument('--PasswordChangeOnFirstAccess', type=int,  choices=[0, 1], help='Determine if a user is required to change the password when the user logs in to the management server for the first time. Note that the feature is not applied to IPMI user accounts.')
    argget.add_argument('--PasswordChangeOnNextLogin', type=int,  choices=[0, 1], help='A manufacturing option is provided to reset the default USERID profile after the first successful login. When PasswordChangeOnNextLogin is required, the default password must be changed before the account can be used. The new password is subject to all active password enforcement rules. Note that the feature is not applied to IPMI and SNMP user accounts.')

    argget.add_argument('--PasswordExpirationPeriodDays', type=int, help='The amount of time, in days, that a user may use a password before it must be changed. Smaller values reduce the amount of time for attackers to guess passwords. If set to 0, passwords never expire.')
    argget.add_argument('--PasswordExpirationWarningPeriod', type=int, help='The amount of time, in days, before password expiration that users will begin to receive warnings about the impending expiration of the user password. If set to 0, users are never warned.Password expiration warning period must be less than password expiration period.')
    argget.add_argument('--MinimumPasswordLength', type=str, help='The minimum number of characters that can be used to specify a valid password.')
    argget.add_argument('--MinimumPasswordReuseCycle', type=int, help='The minimum number of times that a user must enter a unique password when changing the password before the user can start to reuse passwords. A higher number enhances security. If set to 0, passwords may be reused immediately.')
    argget.add_argument('--MinimumPasswordChangeInterval', type=int, help='Minimum amount of time, in hours, that must elapse before a user may change a password again after it has been changed once. The value specified for this setting cannot exceed the value specified for the password expiration period. A small value allows users to more quickly use old passwords. If set to 0, passwords may be changed immediately.')
    argget.add_argument('--LockThreshold', type=int, help='The maximum number of times that a user can attempt to log in with an incorrect password before the user account is locked out. The number specified for the lockout period after maximum login failures determines how long the user account is locked out. Accounts that are locked cannot be used to gain access to the system even if a valid password is provided. If set to 0, accounts are never locked. The failed login counter is reset to zero after a successful login.')
    argget.add_argument('--LockDuration', type=int, help='Minimum amount of time, in minutes, that must pass before a user that was locked out can attempt to log back in again. If set to 0, the account remains locked until an administrator explicitly unlocks it. A setting of 0 can make your system more exposed to serious denial of service attacks, where deliberate failed login attempts can leave accounts permanently locked.')


def add_parameter():
    """Add update user password parameter"""
    argget = utils.create_common_parameter_list(description_string="This tool can be used to set BMC user global setting include password policy and web inactivity session timeout.")
    add_helpmessage(argget)
    args = argget.parse_args()
    parameter_info = utils.parse_parameter(args)

    globalsetting_dict = {}
    if args.PasswordChangeOnFirstAccess is not None:
        globalsetting_dict["PasswordChangeOnFirstAccess"] = bool(args.PasswordChangeOnFirstAccess)
    if args.PasswordChangeOnNextLogin is not None:
        globalsetting_dict["PasswordChangeOnNextLogin"] = bool(args.PasswordChangeOnNextLogin)
    if args.PasswordExpirationPeriodDays is not None:
        globalsetting_dict["PasswordExpirationPeriodDays"] = int(args.PasswordExpirationPeriodDays)
    if args.PasswordExpirationWarningPeriod is not None:
        globalsetting_dict["PasswordExpirationWarningPeriod"] = int(args.PasswordExpirationWarningPeriod)
    if args.MinimumPasswordLength is not None:
        globalsetting_dict["PasswordLength"] = int(args.MinimumPasswordLength)
    if args.MinimumPasswordReuseCycle is not None:
        globalsetting_dict["MinimumPasswordReuseCycle"] = int(args.MinimumPasswordReuseCycle)
    if args.MinimumPasswordChangeInterval is not None:
        globalsetting_dict["MinimumPasswordChangeIntervalHours"] = int(args.MinimumPasswordChangeInterval)
    if args.LockThreshold is not None:
        globalsetting_dict["AccountLockoutThreshold"] = int(args.LockThreshold)
    if args.LockDuration is not None:
        globalsetting_dict["AccountLockoutDuration"] = int(args.LockDuration)

    parameter_info["globalsetting_dict"] = globalsetting_dict
    return parameter_info


if __name__ == '__main__':
    # Get parameters from config.ini and/or command line
    parameter_info = add_parameter()

    # Get connection info from the parameters user specified
    ip = parameter_info['ip']
    login_account = parameter_info["user"]
    login_password = parameter_info["passwd"]

    # check the parameters user specified
    if not parameter_info["globalsetting_dict"]:
        sys.stderr.write("Please run the command 'python %s -h' to view the help info" % sys.argv[0])
        sys.exit(1)

    # Update user password result and check result   
    result = lenovo_set_bmc_user_global(ip, login_account, login_password, parameter_info["globalsetting_dict"])
    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['msg'], sort_keys=True, indent=2))
    else:
        sys.stderr.write(result['msg'])

