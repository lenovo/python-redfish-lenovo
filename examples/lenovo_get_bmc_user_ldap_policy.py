###
#
# Lenovo Redfish examples - Get BMC authentication method (local or ldap)
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

def lenovo_get_bmc_user_ldap_policy(ip, login_account, login_password):
    """get BMC authentication method
        :params ip: BMC IP address
        :type ip: string
        :params login_account: BMC user name
        :type login_account: string
        :params login_password: BMC user password
        :type login_password: string
        :returns: returns get BMC authentication method result when succeeded or error message when failed
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
        # Get root service resource
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
        logon_dict = {}
        if "LocalAccountAuth" in response_accounts_url.dict:
            value = response_accounts_url.dict["LocalAccountAuth"]
            mapdict = {"Enabled": "LocalOnly", "Disabled": "LDAPOnly", "Fallback": "LDAPFirstThenLocal", "LocalFirst": "LocalFirstThenLDAP"}
            if value in mapdict:
                logon_dict["AuthenticationMethod"] = mapdict[value]
            else:
                logon_dict["AuthenticationMethod"] = value
            result = {'ret': True, 'msg': logon_dict}
            return result

        # Use Oem property AuthenticationMethod instead if standard not existing
        if "Oem" in response_accounts_url.dict and response_accounts_url.dict["Oem"] and "Lenovo" in response_accounts_url.dict["Oem"]:
            if "AuthenticationMethod" in response_accounts_url.dict["Oem"]["Lenovo"]:
                logon_dict["AuthenticationMethod"] = response_accounts_url.dict["Oem"]["Lenovo"]["AuthenticationMethod"]
                result = {'ret': True, 'msg': logon_dict}
                return result

        # For ThinkSystem SR635/SR655
        if "Oem" in response_accounts_url.dict and response_accounts_url.dict["Oem"] and "Ami" in response_accounts_url.dict["Oem"]:
            result = {'ret': False, 'msg': 'Both local user and ldap can be supported. But policy setting is not supported.'}
            return result

        # No related resource found
        result = {'ret': False, 'msg': 'Only local user is supported'}
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


if __name__ == '__main__':
    # Get parameters from config.ini and/or command line
    argget = utils.create_common_parameter_list()
    args = argget.parse_args()
    parameter_info = utils.parse_parameter(args)

    # Get connection info from the parameters user specified
    ip = parameter_info['ip']
    login_account = parameter_info["user"]
    login_password = parameter_info["passwd"]

    # Get logon mode and check result
    result = lenovo_get_bmc_user_ldap_policy(ip, login_account, login_password)
    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['msg'], sort_keys=True, indent=2) + '\n')
    else:
        sys.stderr.write(result['msg'] + '\n')
        sys.exit(1)

