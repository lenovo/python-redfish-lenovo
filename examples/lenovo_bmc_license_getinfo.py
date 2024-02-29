###
#
# Lenovo Redfish examples - BMC license getinfo
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
import traceback
import lenovo_utils as utils


def lenovo_bmc_license_getinfo(ip, login_account, login_password):
    """BMC license getinfo
        :params ip: BMC IP address
        :type ip: string
        :params login_account: BMC user name
        :type login_account: string
        :params login_password: BMC user password
        :type login_password: string
        :returns: returns success message result when succeeded or error message when failed
        """

    result = {}
    license_details = []

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
    response_licenses_urls = []
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
            response_licenses_url = REDFISH_OBJ.get(licenses_url, None)
            if response_licenses_url.status != 200:
                error_message = utils.get_extended_error(response_licenses_url)
                result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % (
                    licenses_url, response_licenses_url.status, error_message)}
                REDFISH_OBJ.logout()
                return result 
            response_licenses_urls.append(response_licenses_url)          
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

            # Get license key collection
            request_url = response_url.dict['Keys']['@odata.id']
            response_url = REDFISH_OBJ.get(request_url, None)
            if response_url.status != 200:
                error_message = utils.get_extended_error(response_url)
                result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % (
                    request_url, response_url.status, error_message)}
                REDFISH_OBJ.logout()
                return result
            response_licenses_urls.append(response_url) 

    for response_licenses_url in response_licenses_urls:
        if 'Members' in response_licenses_url.dict:                
            for request in response_licenses_url.dict['Members']:
                license_detail = {}
                request_url = request['@odata.id']
                response_url = REDFISH_OBJ.get(request_url, None)
                if response_url.status != 200:
                    error_message = utils.get_extended_error(response_url)
                    result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % (
                        request_url, response_url.status, error_message)}
                    REDFISH_OBJ.logout()
                    return result
                
                for property in ['Id', 'Name', 'Expires', 'Status', 'IdTypes', 'UseCount', 'RemainingUseCount', 'DescTypeCode', 'Identifier', 'Description', 'Manufacturer','Removable','EntitlementId']:
                    if property in response_url.dict.keys():
                        license_detail[property] = response_url.dict[property]
                    elif "Oem" in response_url.dict.keys() and "Lenovo" in response_url.dict["Oem"] and property in response_url.dict["Oem"]["Lenovo"]:
                        license_detail[property] = response_url.dict["Oem"]["Lenovo"][property]
                license_details.append(license_detail)

        result['ret'] = True
        result['entries'] = license_details
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


def add_parameter():
    """Add license getinfo parameter"""
    parameter_info = {}
    argget = utils.create_common_parameter_list()
    args = argget.parse_args()
    parameter_info = utils.parse_parameter(args)
    return parameter_info


if __name__ == '__main__':
    # Get parameters from config.ini or command line
    parameter_info = add_parameter()
    ip = parameter_info['ip']
    login_account = parameter_info["user"]
    login_password = parameter_info["passwd"]

    # BMC license getinfo and check result
    result = lenovo_bmc_license_getinfo(ip, login_account, login_password)
    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['entries'], sort_keys=True, indent=2) + '\n')
    else:
        sys.stderr.write(result['msg'] + '\n')
        sys.exit(1)

