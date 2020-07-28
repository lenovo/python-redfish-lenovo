###
#
# Lenovo Redfish examples - delete alert recipient specified
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

def lenovo_del_alert_recipient(ip, login_account, login_password, index_id):
    """delete bmc alert recipient
    :params ip: BMC IP address
    :type ip: string
    :params login_account: BMC user name
    :type login_account: string
    :params login_password: BMC user password
    :type login_password: string
    :params index_id: Id of alert recipient
    :type index_id: string
    :returns: returns the result to delete alert recipient or error message when failed
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
            result = {'ret': False, 'msg': "No recipients exist."}
            return result
        
        # Find url of the recipient specified
        recipient_url = ''
        for member in response_recipients_url.dict['Members']:
            if index_id == member['@odata.id'].split("/")[-1]:
                recipient_url = member['@odata.id']
                break
        
        if recipient_url == '':
           result = {'ret': False, 'msg': "The recipient specified does not exist."}
           return result
        
        headers = {"Content-Type": "application/json"}
        response_del_recipient = REDFISH_OBJ.delete(recipient_url, headers=headers)
        if response_del_recipient.status in [200, 204]:
            result = {"ret": True, "msg": "Delete alert recipient with Id %s successfully" % index_id}
            return result
        else:
            error_message = utils.get_extended_error(response_del_recipient)
            result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % (  \
                      recipient_url, response_del_recipient.status, error_message)}
            return result

    except Exception as e:
        result = {'ret': False, 'msg': "Error message %s" %e}
        return result
    finally:
        # Logout of the current session
        try:
            REDFISH_OBJ.logout()
        except:
            pass


def add_parameter():
    """Add Id parameter to specify the alert recipient"""
    argget = utils.create_common_parameter_list(description_string="This tool can be used to get BMC alert recipients.")
    argget.add_argument('--Id', type=int,  required=True, choices=range(1, 13), help='Id of the recipient, scope is 1 ~ 12. ')
    args = argget.parse_args()
    parameter_info = utils.parse_parameter(args)
    parameter_info["Id"] = str(args.Id)
    return parameter_info


if __name__ == '__main__':
    # Get parameters from config.ini and/or command line
    parameter_info = add_parameter()

    # Get connection info from the parameters user specified
    ip = parameter_info['ip']
    login_account = parameter_info["user"]
    login_password = parameter_info["passwd"]
    index_id = parameter_info["Id"]

    # Delete the alert recipient specified by Id and check result   
    result = lenovo_del_alert_recipient(ip, login_account, login_password, index_id)
    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['msg'], sort_keys=True, indent=2))
    else:
        sys.stderr.write(result['msg'] + '\n')

