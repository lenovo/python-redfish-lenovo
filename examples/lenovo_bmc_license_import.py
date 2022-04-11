###
#
# Lenovo Redfish examples - BMC license import
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
import traceback
import base64
import lenovo_utils as utils


def lenovo_bmc_license_import(ip, login_account, login_password, license_file):
    """BMC license import
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

    # check file existing
    if not os.path.exists(license_file):
        result = {'ret': False, 'msg': "Specified file %s does not exist. Please check your license file path." % (license_file)}
        return result

    # Create a REDFISH object
    login_host = "https://" + ip
    REDFISH_OBJ = redfish.redfish_client(base_url=login_host, username=login_account, timeout=utils.g_timeout,
                                         password=login_password, default_prefix='/redfish/v1', cafile=utils.g_CAFILE)

    # Login into the server and create a session
    try:
        REDFISH_OBJ.login(auth=utils.g_AUTH)
    except:
        traceback.print_exc()
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
    
    # Get LicenseService resource
    if 'LicenseService' in response_base_url.dict:
        licenseService_url = response_base_url.dict['LicenseService']['@odata.id']
        response_licenseService_url = REDFISH_OBJ.get(licenseService_url, None)       
        if response_licenseService_url.status != 200:
            error_message = utils.get_extended_error(response_licenseService_url)
            result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % (
                licenseService_url, response_licenseService_url.status, error_message)}
            REDFISH_OBJ.logout()
            return result

        if 'Licenses' in response_licenseService_url.dict:
            licenses_url = response_licenseService_url.dict['Licenses']['@odata.id']
            
            # Get data from license file
            try:
                with open(license_file, 'rb') as f1:
                    base64_b = base64.b64encode(f1.read())
                    base64_str = base64_b.decode('utf-8') 
            except Exception as e:
                traceback.print_exc()
                result = {'ret': False, 'msg': "Failed to open file %s. %s" % (license_file, str(e))}
                REDFISH_OBJ.logout()
                return result
            
            request_body = {'LicenseString': src}  

            # Perform post to import license key
            response_url = REDFISH_OBJ.post(licenses_url, body=request_body)
            if response_url.status not in [200, 201, 202, 204]:
                error_message = utils.get_extended_error(response_url)
                result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % (
                    request_url, response_url.status, error_message)}
            else:
                result = {'ret': True,
                        'msg':"BMC license import successfully"}
            try:
                REDFISH_OBJ.logout()
            except:
                pass
            return result
    else:
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

            # Get data from license file
            try:
                size = os.path.getsize(license_file)
                license_fhandle = open(license_file, 'rb')
            except Exception as e:
                traceback.print_exc()
                result = {'ret': False, 'msg': "Failed to open file %s. %s" % (license_file, str(e))}
                REDFISH_OBJ.logout()
                return result
            bytelist = list()
            for i in range(size):
                data = license_fhandle.read(1)
                elem = struct.unpack("B", data)[0]
                bytelist.append(elem)
            license_fhandle.close()
            request_body = {'Bytes': bytelist}

            # Perform post to import license key
            request_url = response_url.dict['Keys']['@odata.id']
            response_url = REDFISH_OBJ.post(request_url, body=request_body)
            if response_url.status not in [200, 201, 202, 204]:
                error_message = utils.get_extended_error(response_url)
                result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % (
                    request_url, response_url.status, error_message)}
            else:
                result = {'ret': True,
                        'msg':"BMC license import successfully"}
            try:
                REDFISH_OBJ.logout()
            except:
                pass
            return result

    result = {'ret': False, 'msg': "Not support license via Redfish."}
    try:
        REDFISH_OBJ.logout()
    except:
        pass
    return result


def add_helpmessage(parser):
    parser.add_argument('--licensefile', type=str, required=True, help='A file that contains the license key you want to import')


def add_parameter():
    """Add license import parameter"""
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

    # BMC license import and check result
    result = lenovo_bmc_license_import(ip, login_account, login_password, license_file)
    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['msg'], sort_keys=True, indent=2))
    else:
        sys.stderr.write(result['msg'] + '\n')
        sys.exit(1)

