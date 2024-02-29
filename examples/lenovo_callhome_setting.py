###
#
# Lenovo Redfish examples - Call Home setting
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


def lenovo_callhome_setting(ip, login_account, login_password, callhomesetting_dict, httpproxy_dict):
    """ Call Home setting
        :params ip: BMC IP address
        :type ip: string
        :params login_account: BMC user name
        :type login_account: string
        :params login_password: BMC user password
        :type login_password: string
        :params callhomesetting_dict: call home setting
        :type callhomesetting_dict: string
        :params httpproxy_dict: http proxy setting
        :type httpproxy_dict: string
        :returns: returns set call home result when succeeded or error message when failed
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
    
    if "AgreementAccepted" in response_url.dict:
        callhome_setting = {}
        if not response_url.dict['AgreementAccepted']:
            callhome_setting['AgreementAccepted'] = True
        
        # Use call home setting to update callhome_setting dict
        if "CallHomeEnabled" in callhomesetting_dict:
            callhome_setting['CallHomeEnabled'] = callhomesetting_dict['CallHomeEnabled']
        if "CountryCode" in callhomesetting_dict:
            callhome_setting['CountryCode'] = callhomesetting_dict['CountryCode']
        
        for item_name in ["ContactName", "Phone","Email", "CompanyName",
                          "City", "StateOrProvince", "Address", "PostalCode", 
                          "AlternateContactName", "AlternatePhone",
                          "AlternateEmail", "AlternateCompanyName",
                          "AlternateCity", "AlternateStateOrProvince",
                          "AlternateAddress", "AlternatePostalCode",]:
            if item_name in callhomesetting_dict:
                if item_name in response_url.dict['CallHomeSettings']:
                    if 'CallHomeSettings' not in callhome_setting:
                        callhome_setting['CallHomeSettings'] = {}
                    callhome_setting['CallHomeSettings'][item_name] = callhomesetting_dict[item_name]
                    
        for item_name in ["HTTPProxyLocation","HTTPProxyPort","HTTPProxyEnabled","HTTPProxyUserName", "HTTPProxyPassword"]:
            if item_name in httpproxy_dict:
                if item_name in response_url.dict['HTTPProxy']:
                    if 'HTTPProxy' not in callhome_setting:
                        callhome_setting['HTTPProxy'] = {}
                    callhome_setting['HTTPProxy'][item_name] = httpproxy_dict[item_name]
        
        # Perform patch to change setting
        if "@odata.etag" in response_url.dict:
            etag = response_url.dict['@odata.etag']
        else:
            etag = ""
        headers = {"If-Match": etag}
        response_modified = REDFISH_OBJ.patch(advisor_url, body=callhome_setting, headers=headers)
        if response_modified.status in [200,204]:
            result = {'ret': True, 'msg': "The call home setting is successfully updated."}
            return result
        else:
            error_message = utils.get_extended_error(response_modified)
            result = {'ret': False, 'msg': "Update call home setting failed, url '%s' response error code %s \nerror_message: %s" % (advisor_url, response_modified.status, error_message)}
            return result
    else:
        result = {'ret': False, 'msg': 'Call home setting is not supported.'}
    
    try:
        REDFISH_OBJ.logout()
    except:
        pass
    return result

def add_helpmessage(argget):
    # argget.add_argument('--AgreementAccepted', default='1', type=str, choices=['0', '1'], help='Agree or disagree "Call Home User Agreement". This property only can be updated from false to true. Note that you must read and accept the terms and conditions in "Call Home User Agreement" before enabling the Call Home support.')
    argget.add_argument('--CountryCode', type=str, choices=["AO","AR","AM","AU","AT","AZ","BS","BB","BY","BE","BM","BW","BR","BN","BG","BI","CA","KY","CL","CN","CO","HR","CY","CZ","DK","EC","EG","ER","EE","ET","FI","FR","GE","DE","GH","GR","GU","GY","HK","HU","IN","ID","IE","IL","IT","JM","JP","KZ","KE","KR","KG","LV","LR","LT","LU","MO","MW","MY","MT","MX","MA","MZ","NL","NZ","NG","NO","PK","PE","PH","PL","PT","PR","RO","RU","RW","LC","ST","SN","RS","SL","SG","SK","SI","ZA","ES","LK","SR","SE","CH","TW","TJ","TZ","TH","TT","TN","TR","TM","UG","UA","GB","US","US","UY","UZ","VE","VN","VI","ZM","ZW"], help='Indicates the country code.')
    argget.add_argument('--CallHomeEnabled', type=int, default=1, choices=[0, 1], help='Disable or Enable call home, 0: Disable, 1: Enable. Default is Enable. Note: CallHomeEnabled needs to be enabled when reporting to Lenovo Service.')
    # CallHomeSettings
    argget.add_argument('--ContactName', type=str, help='Primary contact name, the maximum length is 30 characters, and special characters & < > are not allowed.')
    argget.add_argument('--Phone', type=str, help='Primary contact phone, the property is limited to 5~30 charcters and only numbers are allowed.')
    argget.add_argument('--Email', type=str, help='Primary contact Email.')
    argget.add_argument('--PostalCode', type=str, help='Primary contact postal code, the maximum length of this property is 9 characters.')
    argget.add_argument('--CompanyName', type=str, help='Primary contact company name, the maximum length is 30 characters, and special characters & < > are not allowed.')
    argget.add_argument('--Address', type=str, help='Primary contact address, the maximum length is 30 characters, and special characters & < > are not allowed.')
    argget.add_argument('--City', type=str, help='Primary contact city, the maximum length is 30 characters.')
    argget.add_argument('--StateOrProvince', type=str, help='Primary contact state or province, the maximum length is 30 characters.')
    argget.add_argument('--AlternateContactName', type=str, help='Alternate contact name, the maximum length is 30 characters, and special characters & < > are not allowed.')
    argget.add_argument('--AlternatePhone', type=str, help='Alternate contact phone, the property is limited to 5~30 charcters and only numbers are allowed.')
    argget.add_argument('--AlternateEmail', type=str, help='Alternate contact Email.')
    argget.add_argument('--AlternatePostalCode', type=str, help='Alternate contact postal code, the maximum length of this property is 9 characters.')
    argget.add_argument('--AlternateCompanyName', type=str, help='Alternate contact company name, the maximum length is 30 characters, and special characters & < > are not allowed.')
    argget.add_argument('--AlternateAddress', type=str, help='Alternate contact address, the maximum length is 30 characters, and special characters & < > are not allowed.')
    argget.add_argument('--AlternateCity', type=str, help='Alternate contact city, the maximum length is 30 characters.')
    argget.add_argument('--AlternateStateOrProvince', type=str, help='Alternate contact state or province, the maximum length is 30 characters.')
    # HTTPProxy
    argget.add_argument('--HTTPProxyEnabled', default=1, type=int, choices=[0, 1], help='Disable or Enable http proxy, 0: Disable, 1: Enable. Default is Enable. Note: HTTPProxyEnabled cannot be set to true while HTTPProxyLocation is an empty string; HTTPProxyLocation cannot be set to an empty string while HTTPProxyEnabled is true.')
    argget.add_argument('--HTTPProxyLocation', type=str, help='Http proxy Server Address, it can only accept a maximum of 63 characters, allowing users to specify IP address or hostname.')
    argget.add_argument('--HTTPProxyPort', default=3128, type=int, help='Http proxy port, the range is from 1 to 65535.')
    argget.add_argument('--HTTPProxyUserName', type=str, help='Http proxy user name if proxy needs authentication.')
    argget.add_argument('--HTTPProxyPassword', type=str, help='Http proxy password if proxy needs authentication.')



def add_parameter():
    """Add call home setting parameter"""
    argget = utils.create_common_parameter_list(description_string="This tool can be used to set call home setting including http proxy.")
    add_helpmessage(argget)
    args = argget.parse_args()
    parameter_info = utils.parse_parameter(args)
    
    callhomesetting_dict = {}
    if args.CountryCode is not None:
        callhomesetting_dict["CountryCode"] = args.CountryCode
    if args.CallHomeEnabled is not None:
        callhomesetting_dict["CallHomeEnabled"] = bool(args.CallHomeEnabled)

    if args.ContactName is not None:
        callhomesetting_dict["ContactName"] = args.ContactName
    if args.Phone is not None:
        callhomesetting_dict["Phone"] = args.Phone
    if args.Email is not None:
        callhomesetting_dict["Email"] = args.Email
    if args.PostalCode is not None:
        callhomesetting_dict["PostalCode"] = args.PostalCode
    if args.CompanyName is not None:
        callhomesetting_dict["CompanyName"] = args.CompanyName
    if args.Address is not None:
        callhomesetting_dict["Address"] = args.Address
    if args.City is not None:
        callhomesetting_dict["City"] = args.City
    if args.StateOrProvince is not None:
        callhomesetting_dict["StateOrProvince"] = args.StateOrProvince
    
    if args.AlternateContactName is not None:
        callhomesetting_dict["AlternateContactName"] = args.AlternateContactName
    if args.AlternatePhone is not None:
        callhomesetting_dict["AlternatePhone"] = args.AlternatePhone
    if args.AlternateEmail is not None:
        callhomesetting_dict["AlternateEmail"] = args.AlternateEmail
    if args.AlternatePostalCode is not None:
        callhomesetting_dict["AlternatePostalCode"] = args.AlternatePostalCode
    if args.AlternateCompanyName is not None:
        callhomesetting_dict["AlternateCompanyName"] = args.AlternateCompanyName
    if args.AlternateAddress is not None:
        callhomesetting_dict["AlternateAddress"] = args.AlternateAddress
    if args.AlternateCity is not None:
        callhomesetting_dict["AlternateCity"] = args.AlternateCity
    if args.AlternateStateOrProvince is not None:
        callhomesetting_dict["AlternateStateOrProvince"] = args.AlternateStateOrProvince
    
    parameter_info["callhomesetting_dict"] = callhomesetting_dict
    
    
    httpproxy_dict = {}
    if args.HTTPProxyEnabled is not None:
        httpproxy_dict["HTTPProxyEnabled"] = bool(args.HTTPProxyEnabled)
    if args.HTTPProxyLocation is not None:
        httpproxy_dict["HTTPProxyLocation"] = args.HTTPProxyLocation
    if args.HTTPProxyPort is not None:
        httpproxy_dict["HTTPProxyPort"] = args.HTTPProxyPort
    if args.HTTPProxyUserName is not None:
        httpproxy_dict["HTTPProxyUserName"] = args.HTTPProxyUserName
    if args.HTTPProxyPassword is not None:
        httpproxy_dict["HTTPProxyPassword"] = args.HTTPProxyPassword
        
    parameter_info["httpproxy_dict"] = httpproxy_dict
    return parameter_info


if __name__ == '__main__':
    # Get parameters from config.ini and/or command line
    parameter_info = add_parameter()

    # Get connection info from the parameters user specified
    ip = parameter_info['ip']
    login_account = parameter_info["user"]
    login_password = parameter_info["passwd"]

    # check the parameters user specified
    if not parameter_info["callhomesetting_dict"] and not parameter_info["httpproxy_dict"]:
        sys.stderr.write("Please run the command 'python %s -h' to view the help info" % sys.argv[0])
        sys.exit(1)

    # Set callhome and check result   
    result = lenovo_callhome_setting(ip, login_account, login_password, parameter_info["callhomesetting_dict"], parameter_info["httpproxy_dict"])
    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['msg'], sort_keys=True, indent=2) + '\n')
    else:
        sys.stderr.write(result['msg'] + '\n')
        sys.exit(1)

