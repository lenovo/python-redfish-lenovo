###
#
# Lenovo Redfish examples - BMC license delete
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

import sys, os, json
import redfish
import lenovo_utils as utils


def lenovo_bmc_license_delete(ip, login_account, login_password, key_id):
    """BMC license delete
        :params ip: BMC IP address
        :type ip: string
        :params login_account: BMC user name
        :type login_account: string
        :params login_password: BMC user password
        :type login_password: string
        :params key_id: license key id by user specified
        :type key_id: string
        :returns: returns success message result when succeeded or error message when failed
        """

    result = {}

    # Create a REDFISH object
    login_host = "https://" + ip
    REDFISH_OBJ = redfish.redfish_client(base_url=login_host, username=login_account, timeout=utils.g_timeout,
                                         password=login_password, default_prefix='/redfish/v1', cafile=utils.g_CAFILE)

    # Login into the server and create a session
    try:
        REDFISH_OBJ.login(auth=utils.g_AUTH)
    except:
        result = {'ret': False, 'msg': "Please check the username, password, IP is correct\n"}
        return result

    # Get ServiceBase resource
    response_base_url = REDFISH_OBJ.get('/redfish/v1', None)
    if response_base_url.status != 200:
        error_message = utils.get_extended_error(response_base_url)
        result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % (
            '/redfish/v1', response_base_url.status, error_message)}
        REDFISH_OBJ.logout()
        return result

    # Get Manager collection resource
    manager_url = response_base_url.dict['Managers']['@odata.id']
    response_manager_url = REDFISH_OBJ.get(manager_url, None)
    if response_manager_url.status != 200:
        error_message = utils.get_extended_error(response_manager_url)
        result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % (
            manager_url, response_manager_url.status, error_message)}
        REDFISH_OBJ.logout()
        return result

    # Get Manager resource
    for request in response_manager_url.dict['Members']:
        request_url = request['@odata.id']
        response_url = REDFISH_OBJ.get(request_url, None)
        if response_url.status != 200:
            error_message = utils.get_extended_error(response_url)
            result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % (
                request_url, response_url.status, error_message)}
            REDFISH_OBJ.logout()
            return result

        # Get bmc license url
        if 'Oem' in response_url.dict and 'Lenovo' in response_url.dict['Oem'] and 'FoD' in response_url.dict['Oem']['Lenovo']:
            request_url = response_url.dict['Oem']['Lenovo']['FoD']['@odata.id']
        else:
            break

        response_url = REDFISH_OBJ.get(request_url, None)
        if response_url.status != 200:
            error_message = utils.get_extended_error(response_url)
            result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % (
                request_url, response_url.status, error_message)}
            REDFISH_OBJ.logout()
            return result

        if 'Keys' not in response_url.dict:
            break

        # Get license key collection to check key id validity
        request_url = response_url.dict['Keys']['@odata.id']
        response_url = REDFISH_OBJ.get(request_url, None)
        if response_url.status != 200:
            error_message = utils.get_extended_error(response_url)
            result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % (
                request_url, response_url.status, error_message)}
            REDFISH_OBJ.logout()
            return result
        request_delete_url = request_url + '/' + key_id
        found = False
        IdList = list()
        if 'Members' in response_url.dict:
            keylink_collection = response_url.dict['Members']
            for keylink in keylink_collection:
                key_url = keylink['@odata.id']
                if request_delete_url == key_url:
                    found = True
                    break
                IdList.append(key_url.split('/')[-1])
        if found == False and len(IdList) > 0:
            result = {'ret': False, 'msg': "The key id %s is not valid. Valid key id list: %s." %(key_id, IdList)}
            REDFISH_OBJ.logout()
            return result
        if found == False and len(IdList) == 0:
            result = {'ret': False, 'msg': "No license key present, no need to delete."}
            REDFISH_OBJ.logout()
            return result
            
        # Perform delete to delete license key
        response_url = REDFISH_OBJ.delete(request_delete_url, None)
        if response_url.status not in [200, 201, 202, 204]:
            error_message = utils.get_extended_error(response_url)
            result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % (
                request_url, response_url.status, error_message)}
        else:
            result = {'ret': True,
                      'msg':"BMC license delete successfully"}
        try:
            REDFISH_OBJ.logout()
        except:
            pass
        return result

    result = {'ret': False, 'msg': "No license resource found, not support."}
    try:
        REDFISH_OBJ.logout()
    except:
        pass
    return result


def add_helpmessage(parser):
    parser.add_argument('--keyid', type=str, required=False, default='1', help='The Id of the license you want to delete, default is 1')


def add_parameter():
    """Add license delete parameter"""
    parameter_info = {}
    argget = utils.create_common_parameter_list()
    add_helpmessage(argget)
    args = argget.parse_args()
    parameter_info = utils.parse_parameter(args)
    parameter_info["keyid"] = args.keyid
    return parameter_info


if __name__ == '__main__':
    # Get parameters from config.ini or command line
    parameter_info = add_parameter()
    ip = parameter_info['ip']
    login_account = parameter_info["user"]
    login_password = parameter_info["passwd"]

    key_id = parameter_info["keyid"]
    # BMC license delete and check result
    result = lenovo_bmc_license_delete(ip, login_account, login_password, key_id)
    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['msg'], sort_keys=True, indent=2))
    else:
        sys.stderr.write(result['msg'] + '\n')

