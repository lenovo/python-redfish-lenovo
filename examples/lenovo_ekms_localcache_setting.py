###
#
# Lenovo Redfish examples - Enable EKMS local cache and cache timeout
# SecureKeyLifecycleManager feature uses centralized ExternalKeyLifecycleManager(EKLM) server to provide keys that unlock storage hardware.
# To use this feature, below steps are needed:
#  - Ensure required license has been imported in BMC(XCC)
#  - Configure EKLM Server(s) in BMC(XCC)
#  - Install/import EKLM server certificate in BMC(XCC) which can be downloaded from EKLM server
#  - Generate EKLM client certificate CSR in BMC(XCC)
#  - Sign the CSR with the CA certificate in EKLM server
#  - Import the signed client certificate in BMC(XCC)
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


def lenovo_ekms_localcache_setting(ip, login_account, login_password, ekms_local_cache_enabled, cache_expiration_time):
    """ Enable EKMS local cache and cache timeout
        :params ip: BMC IP address
        :type ip: string
        :params login_account: BMC user name
        :type login_account: string
        :params login_password: BMC user password
        :type login_password: string
        :params ekms_local_cache_enabled: EKMS local cache key enabled or not
        :type ekms_local_cache_enabled: bool
        :params cache_expiration_time: EKMS local cache expiration time
        :type cache_expiration_time: int
        :returns: returns set ekms local cache result when succeeded or error message when failed
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

    # Access /redfish/v1/Managers/1 to get SecureKeyLifecycleService url
    eklm_url = None
    for request in response_managers_url.dict['Members']:
        request_url = request['@odata.id']
        response_url = REDFISH_OBJ.get(request_url, None)
        if response_url.status != 200:
            error_message = utils.get_extended_error(response_url)
            result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % (
                request_url, response_url.status, error_message)}
            REDFISH_OBJ.logout()
            return result
        if 'SecureKeyLifecycleService' in str(response_url.dict):
            eklm_url = response_url.dict['Oem']['Lenovo']['SecureKeyLifecycleService']['@odata.id']
            break

    # Return here when EKLM feature is not supported
    if eklm_url is None:
        result = {'ret': False, 'msg': 'ExternalKeyLifecycleManager(EKLM) is not supported.'}
        REDFISH_OBJ.logout()
        return result

    # Access /redfish/v1/Managers/1/Oem/Lenovo/SecureKeyLifecycleService
    response_url = REDFISH_OBJ.get(eklm_url, None)
    if response_url.status != 200:
        error_message = utils.get_extended_error(response_url)
        result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % (
            eklm_url, response_url.status, error_message)}
        REDFISH_OBJ.logout()
        return result
    
    if "EKMSLocalCachedKeySettings" in response_url.dict:
        if "@odata.etag" in response_url.dict:
            etag = response_url.dict['@odata.etag']
        else:
            etag = "*"
        headers = {"If-Match": etag}
        cache_setting = { "LocalCachedKeyEnabled": bool(int(ekms_local_cache_enabled)), 
                          "CacheExpirationIntervalHours": cache_expiration_time }
        parameter = {"EKMSLocalCachedKeySettings": cache_setting}
        response_set_cache = REDFISH_OBJ.patch(eklm_url, body=parameter, headers=headers)
        if response_set_cache.status in [200,204]:
                result = {'ret': True,
                          'msg': "PATCH command successfully completed. EKMS LocalCachedKeyEnabled has been set to %s, CacheExpirationIntervalHours has been set to %s." % (bool(int(ekms_local_cache_enabled)), cache_expiration_time)}
        else:
            error_message = utils.get_extended_error(response_set_cache)
            result = {'ret': False, 'msg': "Url '%s' response Error code %s \nerror_message: %s" % ( 
                eklm_url, response_set_cache.status, error_message)}
    else:
        result = {'ret': False, 'msg': 'EKMSLocalCachedKeySettings is not supported.'}
    
    try:
        REDFISH_OBJ.logout()
    except:
        pass
    return result

def add_helpmessage(parser):
    parser.add_argument('--ekms_local_cache_enabled', type=str, choices=['0', '1'], help='Disable or Enable ekms local cache, 0: Disable, 1: Enable.')
    parser.add_argument('--ekms_local_cache_expiration', type=int, default=0, help='Specify the ekms local cache expiration time(Hours).')

def add_parameter():
    """Add set EKMS local cache parameter"""
    argget = utils.create_common_parameter_list()
    add_helpmessage(argget)
    args = argget.parse_args()
    parameter_info = utils.parse_parameter(args)
    parameter_info['ekms_local_cache_enabled'] = args.ekms_local_cache_enabled
    parameter_info['ekms_local_cache_expiration'] = args.ekms_local_cache_expiration
    return parameter_info

if __name__ == '__main__':
    # Get parameters from config.ini and/or command line
    parameter_info = add_parameter()
    
    # Get connection info from the parameters user specified
    ip = parameter_info['ip']
    login_account = parameter_info["user"]
    login_password = parameter_info["passwd"]
    ekms_local_cache_enabled = parameter_info['ekms_local_cache_enabled']
    ekms_local_cache_expiration = parameter_info['ekms_local_cache_expiration']
    
    # Get set EKMS local cache result and check result
    result = lenovo_ekms_localcache_setting(ip, login_account, login_password, ekms_local_cache_enabled, ekms_local_cache_expiration)
    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['msg'], sort_keys=True, indent=2) + '\n')
    else:
        sys.stderr.write(result['msg'] + '\n')
        sys.exit(1)
