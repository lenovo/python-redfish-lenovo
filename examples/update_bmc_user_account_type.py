###
#
# Lenovo Redfish examples - updata user account type
#
# Copyright Notice:
#
# Copyright 2024 Lenovo Corporation
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

def update_bmc_user_account_type(ip, login_account, login_password, username, account_type, new_password=None, account_url=None):
    """update user account type    
    :params ip: BMC IP address
    :type ip: string
    :params login_account: BMC user name
    :type login_account: string
    :params login_password: BMC user password
    :type login_password: string
    :params username: Username to be modified by the user
    :type username: string
    :params account_type: Account type to be modified by the user
    :type account_type: string
    :params new_password: New password for the user specified when IPMI added in account type
    :type new_password: string
    :params account_url: BMC account url
    :type account_url: string
    :returns: returns update user account type result when succeeded or error message when failed
    """
    result = {}
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

    # default user account url, treat userid 1 as default account
    account_x_url = '/redfish/v1/AccountService/Accounts/1'
    parameter = {"AccountTypes": account_type}
    if "IPMI" in account_type:
        if new_password == None:
            result = {'ret': False, 'msg': "You must specify newpassword for the account you want to change because IPMI is specified in account type. \n"}
            return result
        parameter['Password'] = new_password
    
    if account_url != None:
        account_x_url = account_url
    
    etag = ""
    try:
        # get the account url of username
        if username != None:
            # Get url accounts resource
            accounts_url = '/redfish/v1/AccountService/Accounts'
            response_accounts_url = REDFISH_OBJ.get(accounts_url, None)
            if response_accounts_url.status == 200:
                account_count = response_accounts_url.dict["Members@odata.count"]
                # Loop the BMC user list and get all the bmc username
                isUserExisted = False
                for x in range(0, account_count):
                    account_member_url = response_accounts_url.dict["Members"][x]["@odata.id"]
                    response_account_member_url = REDFISH_OBJ.get(account_member_url, None)
                    if response_account_member_url.status == 200:
                        bmc_username = response_account_member_url.dict['UserName']
                        # Update the BMC user account type when the specified BMC username is in the BMC user list.
                        if bmc_username == username:
                            if "@odata.etag" in response_account_member_url.dict:
                                etag = response_account_member_url.dict['@odata.etag']
                            else:
                                etag = ""
                            account_x_url = account_member_url 
                            isUserExisted = True
                            break   
                    # account_member_url response failed
                    else:
                        try:
                            error_message = utils.get_extended_error(response_account_member_url)
                        except:
                            error_message = response_account_member_url
                        result = {'ret': False, 'msg': "response_account_member_url Error code %s \nerror_message: %s" % (
                            response_account_member_url.status, error_message)}
                        return result
                
                if isUserExisted == False:
                    result = {'ret': False, 'msg': "BMC username specified doesn't exist. Please check whether the BMC username is correct."}
                    return result
            else:
                error_message = utils.get_extended_error(response_accounts_url)
                result = {'ret': False, 'msg': "Url '%s' response error code %s \nerror_message: %s" % (accounts_url, response_accounts_url.status, error_message)}
                return result

        headers = {"If-Match": etag}
        response_modified_account_type = REDFISH_OBJ.patch(account_x_url, body=parameter, headers=headers)
        error_message = utils.get_extended_error(response_modified_account_type)
        if response_modified_account_type.status in [200,204]:
            if username != None:
                msg = "Succeeded to update account type of BMC user %s. url is %s." % (username, account_x_url)
            else: 
                msg = "Succeeded to update account type of BMC user. url is %s." % account_x_url
            result = {'ret': True, 'msg': msg}
            return result
        else:
            result = {'ret': False, 'msg': "Failed to update account type of BMC user, url '%s' response error code %s \nerror_message: %s\n" % (account_x_url, response_modified_account_type.status, error_message)}
            return result
    
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


import argparse
def add_helpmessage(argget):
    argget.add_argument('--username', type=str, help='Input the name of BMC user to be updated.')
    argget.add_argument('--accounttype', type=str, required=True, nargs="+", choices=["WebUI","Redfish","ManagerConsole","IPMI","SNMP"], help='Input account type of BMC user')
    argget.add_argument('--newpassword', type=str, help='Input the password for the user specified, only needed when you specified "IPMI" in accounttype.')
    argget.add_argument('--url', type=str, help='Input account url of BMC user to update the account type.(e.g., /redfish/v1/AccountService/Accounts/2)')


def add_parameter():
    """Add update user account type parameter"""
    example = """
    Example:  
        Change the account type for the default BMC account:
            "python update_bmc_user_account_type.py -i 10.10.10.10 -u USERID -p PASSW0RD --accounttype WebUI Redfish"
        Change the account type for the specified user:
            "python update_bmc_user_account_type.py -i 10.10.10.10 -u USERID -p PASSW0RD --username USERNAME --accounttype WebUI Redfish"
            "python update_bmc_user_account_type.py -i 10.10.10.10 -u USERID -p PASSW0RD --accounttype WebUI Redfish --url /redfish/v1/AccountService/Accounts/2"
            "python update_bmc_user_account_type.py -i 10.10.10.10 -u USERID -p PASSW0RD --accounttype WebUI Redfish IPMI --newpassword NEWPASSWORD --url /redfish/v1/AccountService/Accounts/2"
            """
    argget = utils.create_common_parameter_list(example_string=example)
    add_helpmessage(argget)
    args = argget.parse_args()
    parameter_info = utils.parse_parameter(args)
    parameter_info["username"] = args.username
    parameter_info["account_type"] = args.accounttype
    parameter_info["new_password"] = args.newpassword
    parameter_info["account_url"] = args.url
    
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
    account_type = parameter_info['account_type']
    account_url = parameter_info['account_url']
    new_password = parameter_info["new_password"]

    # Update user account type result and check result   
    result = update_bmc_user_account_type(ip, login_account, login_password, username, account_type, new_password, account_url)
    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['msg'], sort_keys=True, indent=2) + '\n')
    else:
        sys.stderr.write(result['msg'] + '\n')
        sys.exit(1)
