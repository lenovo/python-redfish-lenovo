###
#
# Lenovo Redfish examples - Get Call Home
#
# Copyright Notice:
#
# Copyright 2023 Lenovo Corporation
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

import sys, os
import redfish
import json
import traceback
import lenovo_utils as utils


def lenovo_callhome_getinfo(ip, login_account, login_password):
    """ Get Call Home
        :params ip: BMC IP address
        :type ip: string
        :params login_account: BMC user name
        :type login_account: string
        :params login_password: BMC user password
        :type login_password: string
        :returns: returns get call home result when succeeded or error message when failed
        """

    result = {}

    # Create a REDFISH object
    login_host = "https://" + ip
    REDFISH_OBJ = redfish.redfish_client(base_url=login_host, username=login_account, timeout=utils.g_timeout,
                                         password=login_password, default_prefix='/redfish/v1')

    # Login into the server and create a session
    try:
        REDFISH_OBJ.login(auth="session")
    except:
        traceback.print_exc()
        result = {'ret': False, 'msg': "Please check the username, password, IP is correct\n"}
        return result

    # Get /redfish/v1
    try:
        response_base_url = REDFISH_OBJ.get('/redfish/v1', None)
        if response_base_url.status != 200:
            error_message = utils.get_extended_error(response_base_url)
            result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % (
                '/redfish/v1', response_base_url.status, error_message)}
            REDFISH_OBJ.logout()
            return result

        # Get /redfish/v1/Managers
        managers_url = response_base_url.dict['Managers']['@odata.id']
        response_managers_url = REDFISH_OBJ.get(managers_url, None)
        if response_managers_url.status != 200:
            error_message = utils.get_extended_error(response_managers_url)
            result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % (
                managers_url, response_managers_url.status, error_message)}
            REDFISH_OBJ.logout()
            return result

        # Access /redfish/v1/Managers/1 to get ServiceAdvisor url
        advisor_url = None
        for request in response_managers_url.dict['Members']:
            request_url = request['@odata.id']
            response_url = REDFISH_OBJ.get(request_url, None)
            if response_url.status != 200:
                error_message = utils.get_extended_error(response_url)
                result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % (
                    request_url, response_url.status, error_message)}
                REDFISH_OBJ.logout()
                return result
            if 'ServiceAdvisor' in str(response_url.dict):
                advisor_url = response_url.dict['Oem']['Lenovo']['ServiceAdvisor']
                break

        # Return here when ServiceAdvisor feature is not supported
        if advisor_url is None:
            result = {'ret': False, 'msg': 'ServiceAdvisor is not supported.'}
            REDFISH_OBJ.logout()
            return result

        # Access /redfish/v1/Managers/1/Oem/Lenovo/ServiceAdvisor
        response_url = REDFISH_OBJ.get(advisor_url, None)
        if response_url.status != 200:
            error_message = utils.get_extended_error(response_url)
            result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % (
                advisor_url, response_url.status, error_message)}
            REDFISH_OBJ.logout()
            return result
        callhome = {}
        if "AgreementAccepted" in response_url.dict:
            callhome['CallHomeSettings'] = response_url.dict['CallHomeSettings']
            callhome['HTTPProxy'] = response_url.dict['HTTPProxy']
            callhome['CallHomeEnabled'] = response_url.dict['CallHomeEnabled']
            callhome['AgreementAccepted'] = response_url.dict['AgreementAccepted']
            callhome['CountryCode'] = response_url.dict['CountryCode']
            result['ret'] = True
            result['entries'] = callhome
            return result
        else:
            result = {'ret': False, 'msg': 'Call home is not supported.'}
            return result
    except Exception as e:
        traceback.print_exc()
        result = {'ret':False, 'msg':"Error message %s" %e}
        return result
    finally:
        try:
            REDFISH_OBJ.logout()
        except:
            pass

def add_parameter():
    """Add parameter"""
    argget = utils.create_common_parameter_list()
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

    result = lenovo_callhome_getinfo(ip, login_account, login_password)
    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['entries'], sort_keys=True, indent=2))
    else:
        sys.stderr.write(result['msg'] + '\n')
        sys.exit(1)


