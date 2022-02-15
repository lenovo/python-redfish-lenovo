###
#
# Lenovo Redfish examples - Set BMC authentication policy (LocalOnly, LDAPOnly, LocalFirstThenLDAP, or LDAPFirstThenLocal)
#
# Copyright Notice:
#
# Copyright 2021 Lenovo Corporation
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

def lenovo_set_bmc_user_ldap_policy(ip, login_account, login_password, policy):
    """set BMC authentication policy
        :params ip: BMC IP address
        :type ip: string
        :params login_account: BMC user name
        :type login_account: string
        :params login_password: BMC user password
        :type login_password: string
        :params policy: Specify how the user attempt to login should be authenticated
        :type policy: string
        :returns: returns set BMC authentication policy result when succeeded or error message when failed
        """
    login_host = "https://" + ip

    # Connect using the BMC address, account name, and password
    # Create a REDFISH object
    REDFISH_OBJ = redfish.redfish_client(base_url=login_host, username=login_account, timeout=utils.g_timeout,
                                         password=login_password, default_prefix='/redfish/v1')

    # Login into the server and create a session
    try:
        REDFISH_OBJ.login(auth="session")
    except:
        traceback.print_exc()
        result = {'ret': False, 'msg': "Please check the username, password, IP is correct\n"}
        return result

    # Get ServiceBase resource
    try:
        # Get root service
        response_base_url = REDFISH_OBJ.get('/redfish/v1', None)
        if response_base_url.status != 200:
            error_message = utils.get_extended_error(response_base_url)
            result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % (
                '/redfish/v1', response_base_url.status, error_message)}
            return result

        # Get AccountService resource
        accounts_url = response_base_url.dict['AccountService']['@odata.id']
        response_accounts_url = REDFISH_OBJ.get(accounts_url, None)
        if response_accounts_url.status != 200:
            error_message = utils.get_extended_error(response_accounts_url)
            result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % (
                accounts_url, response_accounts_url.status, error_message)}
            return result

        # Use standard property LocalAccountAuth first
        request_body = None
        if "LocalAccountAuth" in response_accounts_url.dict:
            current_value = response_accounts_url.dict["LocalAccountAuth"]
            mapdict = {"LocalOnly": "Enabled", "LDAPOnly": "Disabled", "LDAPFirstThenLocal": "Fallback", "LocalFirstThenLDAP": "LocalFirst"}
            if current_value == mapdict[policy]:
                result = {'ret': True, 'msg':"Current policy is already %s, no need to set" %policy}
                return result
            request_body = {"LocalAccountAuth": mapdict[policy]}

        # Use Oem property AuthenticationMethod instead if standard not existing
        if "Oem" in response_accounts_url.dict and response_accounts_url.dict["Oem"] and "Lenovo" in response_accounts_url.dict["Oem"]:
            if "AuthenticationMethod" in response_accounts_url.dict["Oem"]["Lenovo"]:
                current_value = response_accounts_url.dict["Oem"]["Lenovo"]["AuthenticationMethod"]
                if current_value == policy:
                    result = {'ret': True, 'msg':"Current policy is already %s, no need to set" %policy}
                    return result
                request_body = {"Oem":{"Lenovo":{"AuthenticationMethod":policy}}}

        # No related resource found
        if request_body is None:
            # For ThinkSystem SR635/SR655
            if "Oem" in response_accounts_url.dict and response_accounts_url.dict["Oem"] and "Ami" in response_accounts_url.dict["Oem"]:
                result = {'ret': False, 'msg': 'Both local user and ldap can be supported. But policy setting is not supported.'}
                return result


            result = {'ret': False, 'msg': 'Only local user is supported'}
            return result

        # Send patch to change the allowable login policy
        response_accounts_url = REDFISH_OBJ.patch(accounts_url, body=request_body)
        if response_accounts_url.status == 200:
            result = {'ret': True, 'msg':"Successfully set logon policy to %s" %(policy)}
            return result
        else:
            error_message = utils.get_extended_error(response_accounts_url)
            result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % (
                accounts_url, response_accounts_url.status, error_message)}
            return result

    except Exception as e:
        traceback.print_exc()
        result = {'ret': False, 'msg': 'exception msg %s' % e}
        return result
    finally:
        try:
            REDFISH_OBJ.logout()
        except:
            pass


def add_helpmessage(argget):
    argget.add_argument('--policy', type=str,  required=True, choices=["LocalOnly", "LDAPOnly", "LocalFirstThenLDAP", "LDAPFirstThenLocal"],
                        help='Specify how the user attempt to login should be authenticated.'
                             'Support: ["LocalOnly", "LDAPOnly", "LocalFirstThenLDAP", "LDAPFirstThenLocal"]')


def add_parameter():
    """Add set authentication policy parameter"""
    argget = utils.create_common_parameter_list()
    add_helpmessage(argget)
    args = argget.parse_args()
    parameter_info = utils.parse_parameter(args)
    parameter_info["policy"] = args.policy
    return parameter_info


if __name__ == '__main__':
    # Get parameters from config.ini and/or command line
    parameter_info = add_parameter()

    # Get connection info from the parameters user specified
    ip = parameter_info["ip"]
    login_account = parameter_info["user"]
    login_password = parameter_info["passwd"]

    # Get set info from the parameters user specified
    policy = parameter_info["policy"]

    # Set authentication policy and check result
    result = lenovo_set_bmc_user_ldap_policy(ip, login_account, login_password, policy)
    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['msg'], sort_keys=True, indent=2))
    else:
        sys.stderr.write(result['msg'] + '\n')
        sys.exit(1)

