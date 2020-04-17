###
#
# Lenovo Redfish examples - BMC license export
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

import sys, os, json, struct
import redfish
import lenovo_utils as utils


def lenovo_bmc_license_export(ip, login_account, login_password, license_file):
    """BMC license export
        :params ip: BMC IP address
        :type ip: string
        :params login_account: BMC user name
        :type login_account: string
        :params login_password: BMC user password
        :type login_password: string
        :params license_file: license file by user specified
        :type license_file: string
        :returns: returns success message result when succeeded or error message when failed
        """

    result = {}
    license_keys = []

    # check file existing
    if license_file is not None and os.path.exists(license_file):
        result = {'ret': False, 'msg': "Specified file %s exist. Please specify new file name to save exported license." % (license_file)}
        return result

    # Create a REDFISH object
    login_host = "https://" + ip
    REDFISH_OBJ = redfish.redfish_client(base_url=login_host, username=login_account,
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

        # Get license key collection
        request_url = response_url.dict['Keys']['@odata.id']
        response_url = REDFISH_OBJ.get(request_url, None)
        if response_url.status != 200:
            error_message = utils.get_extended_error(response_url)
            result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % (
                request_url, response_url.status, error_message)}
            REDFISH_OBJ.logout()
            return result

        if 'Members' in response_url.dict:
            keylink_collection = response_url.dict['Members']
            for keylink in keylink_collection:
                request_url = keylink['@odata.id']
                response_url = REDFISH_OBJ.get(request_url, None)
                if response_url.status != 200:
                    error_message = utils.get_extended_error(response_url)
                    result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % (
                        request_url, response_url.status, error_message)}
                    REDFISH_OBJ.logout()
                    return result
                if license_file is not None:
                    filename = license_file
                else:
                    filename = 'exported_' + ip + '_license_keyfile_' + request_url.split('/')[-1] + '.key'
                if os.path.exists(filename): 
                    os.remove(filename)
                license_fhandle = open(filename, 'wb+')
                if 'Bytes' in response_url.dict:
                    bytelist = response_url.dict['Bytes']
                    for eachbyte in bytelist:
                        bytes=struct.pack('B', eachbyte)
                        license_fhandle.write(bytes)
                license_fhandle.close()
                license_keys.append(filename)
        if len(license_keys) == 0:
            result['ret'] = False
            result['msg'] = 'No license key present.'
        else:
            result['ret'] = True
            result['msg'] = 'Export license keys successfully. ' + str(license_keys)
        REDFISH_OBJ.logout()
        return result

    result = {'ret': False, 'msg': "Not support license via Redfish."}
    REDFISH_OBJ.logout()
    return result


def add_helpmessage(parser):
    parser.add_argument('--licensefile', type=str, required=False, help='Input the file name that you want to save the exported license, default file: exported_10.10.10.10_license_keyfile_1.key')


def add_parameter():
    """Add license export parameter"""
    parameter_info = {}
    argget = utils.create_common_parameter_list()
    add_helpmessage(argget)
    args = argget.parse_args()
    parameter_info = utils.parse_parameter(args)
    parameter_info["licensefile"] = args.licensefile
    return parameter_info


if __name__ == '__main__':
    # Get parameters from config.ini or command line
    parameter_info = add_parameter()
    ip = parameter_info['ip']
    login_account = parameter_info["user"]
    login_password = parameter_info["passwd"]
    license_file = parameter_info["licensefile"]

    # BMC license export and check result
    result = lenovo_bmc_license_export(ip, login_account, login_password, license_file)
    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['msg'], sort_keys=True, indent=2))
    else:
        sys.stderr.write(result['msg'])

