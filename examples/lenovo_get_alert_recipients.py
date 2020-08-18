###
#
# Lenovo Redfish examples - get alert recipients
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

def lenovo_get_alert_recipients(ip, login_account, login_password):
    """get bmc alert recipients 
    :params ip: BMC IP address
    :type ip: string
    :params login_account: BMC user name
    :type login_account: string
    :params login_password: BMC user password
    :type login_password: string
    :returns: returns bmc alert recipients or error message when failed
    """
    result = {}
    # Connect using the BMC address, account name, and password
    # Create a REDFISH object
    login_host = "https://" + ip
    try:
        # Connect using the BMC address, account name, and password
        # Create a REDFISH object 
        REDFISH_OBJ = redfish.redfish_client(base_url=login_host, username=login_account, 
                                             password=login_password, default_prefix='/redfish/v1', cafile=utils.g_CAFILE, max_retry=3)
        # Login into the server and create a session
        REDFISH_OBJ.login(auth=utils.g_AUTH)
    except Exception as e:
        result = {'ret': False, 'msg': "Error_message: %s. Please check if username, password and IP are correct" % repr(e)}
        return result


    try:
        # Get ServiceBase resource
        response_base_url = REDFISH_OBJ.get('/redfish/v1', None)

        # Get Managers collection resource
        managers_url = response_base_url.dict['Managers']['@odata.id']
        response_managers_url = REDFISH_OBJ.get(managers_url, None)

        # Get Manager resource
        manager_url = response_managers_url.dict['Members'][0]['@odata.id']
        response_manager_url = REDFISH_OBJ.get(manager_url, None)
        
        # Get bmc recipients url
        if 'Oem' in response_manager_url.dict and 'Lenovo' in response_manager_url.dict['Oem'] and 'Recipients' in response_manager_url.dict['Oem']['Lenovo']:
            recipients_url = response_manager_url.dict['Oem']['Lenovo']['Recipients']['@odata.id']
        else:
            result = {'ret': False, 'msg': "No support to add alert recipient."}
            return result
        
        # Get alert recipients
        response_recipients_url = REDFISH_OBJ.get(recipients_url, None)
        if response_recipients_url.dict['Members@odata.count'] == 0:
            result = {'ret': True, 'msg': "No recipients exist.", 'entries':[]}
            return result
        
        all_recipients = []
        items_excluded = ['@odata.type', '@odata.id', '@odata.etag']
        for member in response_recipients_url.dict['Members']:
            recipient_url = member['@odata.id']
            response_recipient_url = REDFISH_OBJ.get(recipient_url, None)
            if response_recipient_url.status not in [200, 201]:
                error_message = utils.get_extended_error(response_recipient_url)
                result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % (
                          recipient_url, response_recipient_url.status, error_message)}
                return result
            recipient_dict = {}
            for key in response_recipient_url.dict:
                if key not in items_excluded:
                    recipient_dict[key] = response_recipient_url.dict[key]
            all_recipients.append(recipient_dict)
        result = {"ret":True,"entries":all_recipients}
        return result

    except Exception as e:
        result = {'ret':False, 'msg':"Error message %s" %e}
        return result
    finally:
        # Logout of the current session
        try:
            REDFISH_OBJ.logout()
        except:
            pass


def add_parameter():
    """Add common parameters"""
    argget = utils.create_common_parameter_list(description_string="This tool can be used to get BMC alert recipients.")
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

    # get alert recipients and check result   
    result = lenovo_get_alert_recipients(ip, login_account, login_password)
    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['entries'], sort_keys=True, indent=2))
    else:
        sys.stderr.write(result['msg'] + '\n')

