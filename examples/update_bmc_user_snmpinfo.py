###
#
# Lenovo Redfish examples - update SNMPv3 settings for a BMC user to receive SNMPv3 TRAPs.
#
# Follow below steps to configure SNMP Alert Recipients
# Step 1: Get SNMP engineid from target server as below (Ex. target server ip is 10.245.39.101)
#         #python3 lenovo_generate_snmp_engineid.py -i 10.245.39.101 -u USERID -p PASSW0RD
#         "80 00 1F 88 04 58 43 43 2D 37 58 30 35 2D 4A 33 30 30 43 4B 56 4E"
# Step 2: Setup and configure your SNMP trap receiver (Ex. receiver ip is 10.245.52.18)
#         Ex. Configure your community for SNMPv1 trap as below in net-snmp's /etc/snmp/snmptrapd.conf
#         authCommunity   log,execute,net mypublic
#         Ex. Configure user info for SNMPv3 trap as below in net-snmp's /etc/snmp/snmptrapd.conf
#         createUser -e 0x80001F88045843432D375830352D4A333030434B564E USERID SHA "PASSW0RD" AES "Aa12345678"
#         Ex. Start the trap receiver after configuration as below for snmptrapd
#         #sudo snmptrapd -c /etc/snmp/snmptrapd.conf -Lo -f
# Step 3: Set SNMP global settings to enable SNMPv1/SNMPv3 traps on target server as below
#         #python3 lenovo_set_snmp_global.py -i 10.245.39.101 -u USERID -p PASSW0RD --CriticalEvents all --WarningEvents all --SystemEvents all --snmpv1_community mypublic --snmpv1_trap enable --location mylocation --contact_person myperson --snmpv3_trap enable
# Step 4: Set SNMPv3 user settings on target server as below (skip this for SNMPv1 only)
#         #python3 update_bmc_user_snmpinfo.py -i 10.245.39.101 -u USERID -p PASSW0RD --username USERID --authentication_protocol HMAC_SHA96 --privacy_protocol CFB128_AES128 --privacy_password Aa12345678
# Step 5: Add SNMPv1 or SNMPv3 protocol subscription on target server as below
#         Ex. Add SNMPv1 subscription
#         #python3 add_event_subscriptions.py -i 10.245.39.101 -u USERID -p PASSW0RD --protocol SNMPv1 --destination 10.245.52.18
#         Ex. Add SNMPv3 subscription
#         #python3 add_event_subscriptions.py -i 10.245.39.101 -u USERID -p PASSW0RD --protocol SNMPv3 --destination USERID@10.245.52.18
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


def update_bmc_user_snmpinfo(ip, login_account, login_password,
        username, authentication_protocol, privacy_protocol, privacy_password):
    """update user snmp info to receive SNMPv3 TRAPs
    :params ip: BMC IP address
    :type ip: string
    :params login_account: BMC user name
    :type login_account: string
    :params login_password: BMC user password
    :type login_password: string
    :params username: Username to be configured for receiving SNMPv3 TRAPs
    :type username: string
    :params authentication_protocol: Specify authentication protocol
    :type authentication_protocol: string
    :params privacy_protocol: Specify privacy protocol
    :type privacy_protocol: string
    :params privacy_password: Specify privacy password
    :type privacy_password: string or None
    :returns: returns success or error message when failed
    """

    result = {}
    # check input parameter
    if authentication_protocol == 'None' and privacy_protocol != 'None':
        result = {'ret': False, 'msg': 'If privacy_protocol is not "None", authentication_protocol cannot be "None".'}
        return result
    if privacy_protocol == 'None' and not (privacy_password is None or privacy_password == ''):
        result = {'ret': False, 'msg': 'If privacy_protocol is "None", privacy_password cannot be set.'}
        return result
    if privacy_protocol != 'None' and (privacy_password is None or privacy_password == ''):
        result = {'ret': False, 'msg': 'privacy_password is missing.'}
        return result
    if privacy_password is not None and privacy_password != '':
        if check_input_password(privacy_password) == False:
            result = {'ret': False, 'msg': 'Invalid privacy_password. Length of privacy_password must be no less than 10. And it must contain at least 1 uppercase letter(A~Z), at least 1 lowercase letter(a~z) and at least 1 digit(0~9).'}
            return result

    try:
        # Connect using the BMC address, account name, and password
        # Create a REDFISH object
        login_host = "https://" + ip
        REDFISH_OBJ = redfish.redfish_client(base_url=login_host, username=login_account, timeout=utils.g_timeout,
                                             password=login_password, default_prefix='/redfish/v1', cafile=utils.g_CAFILE)
        # Login into the server
        REDFISH_OBJ.login(auth="basic")
    except:
        traceback.print_exc()
        result = {'ret': False, 'msg': "Please check the username, password, IP is correct\n"}
        return result

    # change specified username account's snmp info
    try:
        # Get response_base_url resource
        response_base_url = REDFISH_OBJ.get('/redfish/v1', None)

        # Get account service url
        if response_base_url.status == 200:
            account_service_url = response_base_url.dict['AccountService']['@odata.id']
        else:
            error_message = utils.get_extended_error(response_base_url)
            result = {'ret': False, 'msg': "Url '/redfish/v1' response Error code %s \nerror_message: %s" % (
            response_base_url.status, error_message)}
            return result

        # Get AccountService resource
        response_account_service_url = REDFISH_OBJ.get(account_service_url, None)
        if response_account_service_url.status == 200:
            accounts_url = response_account_service_url.dict['Accounts']['@odata.id']
        else:
            error_message = utils.get_extended_error(response_account_service_url)
            result = {'ret': False, 'msg': "Url '%s' response Error code %s \nerror_message: %s" % (account_service_url, response_account_service_url.status, error_message)}
            return result

        # Get BMC user uri list
        response_accounts_url = REDFISH_OBJ.get(accounts_url, None)
        if response_accounts_url.status != 200:
            error_message = utils.get_extended_error(response_accounts_url)
            result = {'ret': False, 'msg': "Url '%s' response error code %s \nerror_message: %s" % (accounts_url,
                response_accounts_url.status, error_message)}
            return result

        account_count = response_accounts_url.dict["Members@odata.count"]
        # Loop the BMC user uri list and get bmc username to locate specified one
        for x in range(0, account_count):
            account_x_url = response_accounts_url.dict["Members"][x]["@odata.id"]
            response_account_x_url = REDFISH_OBJ.get(account_x_url, None)
            if response_account_x_url.status != 200:# account_x_url response failed
                try:
                    error_message = utils.get_extended_error(response_account_x_url)
                except:
                    error_message = response_account_x_url
                result = {'ret': False, 'msg': "response_account_x_url Error code %s \nerror_message: %s" % (
                    response_account_x_url.status, error_message)}
                return result

            if 'SNMP' not in response_account_x_url.dict:
                result = {'ret': False, 'msg': 'Target server does not support SNMP info setting for BMC user.'}
                return result

            bmc_username = response_account_x_url.dict['UserName']
            # Update the BMC user snmp info when the specified BMC username is found.
            if bmc_username == username:
                if "@odata.etag" in response_account_x_url.dict:
                    etag = response_account_x_url.dict['@odata.etag']
                else:
                    etag = ""
                headers = {"If-Match": etag}
                parameter = {
                        "SNMP": {
                            "AuthenticationProtocol": authentication_protocol,
                            "EncryptionProtocol": privacy_protocol
                        }
                    }
                if privacy_password is not None and privacy_password != '':
                    parameter["SNMP"]["EncryptionKey"] = privacy_password
                response_modified = REDFISH_OBJ.patch(account_x_url, body=parameter, headers=headers)
                if response_modified.status in [200,204]:
                    result = {'ret': True, 'msg': "The BMC user '%s' snmp info is successfully updated." % username}
                    return result
                else:
                    error_message = utils.get_extended_error(response_modified)
                    result = {'ret': False, 'msg': "Update BMC user snmp info failed, url '%s' response error code %s \nerror_message: %s" % (account_x_url, response_modified.status, error_message)}
                    return result

        result = {'ret': False, 'msg': "Specified BMC username %s doesn't exist. Please check whether the BMC username is correct." %(username)}
    except Exception as e:
        traceback.print_exc()
        result = {'ret':False, 'msg':"Error message %s" %e}
    finally:
        # Logout
        try:
            REDFISH_OBJ.logout()
        except:
            pass
        return result


def check_input_password(passwordstr):
    if len(passwordstr) < 10 or len(passwordstr) > 32:
        return False
    count_upchar = 0
    count_lochar = 0
    count_num = 0
    for ch in passwordstr:
        val = ord(ch)
        if val >= 65 and val <= 90:
            count_upchar += 1
        elif val >= 97 and val <= 122:
            count_lochar += 1
        elif val >= 48 and val <= 57:
            count_num += 1
    if count_upchar > 0 and count_lochar > 0 and count_num > 0:
        return True
    else:
        return False


import argparse
def add_helpmessage(argget):
    argget.add_argument('--username', required=True, type=str, help='Input the name of BMC user to configure for receiving SNMPv3 TRAPs.')
    argget.add_argument('--authentication_protocol', type=str, default='None', choices=['None', 'HMAC_SHA96'],
            help='Specify the Authentication Protocol as HMAC_SHA96 which is the hash algorithm used by the SNMP V3 security model for the authentication.')
    argget.add_argument('--privacy_protocol', type=str, default='None', choices=['None', 'CBC_DES', 'CFB128_AES128'],
            help='Privacy protocol can be used to encrypt and protect the data transferred between the SNMP client and the agent. The supported methods are CBC_DES and CFB128_AES128.')
    argget.add_argument('--privacy_password', type=str,
            help='Privacy password can be used to encrypt and protect the data transferred between the SNMP client and the agent when privacy protocol is CBC_DES or CFB128_AES128.')


def add_parameter():
    """Add update user snmp info parameter"""
    argget = utils.create_common_parameter_list()
    add_helpmessage(argget)
    args = argget.parse_args()
    parameter_info = utils.parse_parameter(args)
    parameter_info["username"] = args.username
    parameter_info["authentication_protocol"] = args.authentication_protocol
    parameter_info["privacy_protocol"] = args.privacy_protocol
    parameter_info["privacy_password"] = args.privacy_password
    return parameter_info


if __name__ == '__main__':
    # Get parameters from config.ini and/or command line
    parameter_info = add_parameter()

    # Get connection info from the parameters user specified
    ip = parameter_info['ip']
    login_account = parameter_info["user"]
    login_password = parameter_info["passwd"]

    # Get set info from the parameters user specified
    username = parameter_info['username']
    authentication_protocol = parameter_info['authentication_protocol']
    privacy_protocol = parameter_info['privacy_protocol']
    privacy_password = parameter_info['privacy_password']

    # Update user snmp info result and check result   
    result = update_bmc_user_snmpinfo(ip, login_account, login_password, username, authentication_protocol, privacy_protocol, privacy_password)
    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['msg'], sort_keys=True, indent=2))
    else:
        sys.stderr.write(result['msg'] + '\n')
        sys.exit(1)

