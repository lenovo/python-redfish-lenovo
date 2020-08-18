###
#
# Lenovo Redfish examples - Add event subscriptions
#
# Copyright Notice:
#
# Copyright 2018 Lenovo Corporation
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

def add_event_subscriptions(ip, login_account, login_password,destination,eventtypes,context):
    """Add event subscriptions
        :params ip: BMC IP address
        :type ip: string
        :params login_account: BMC user name
        :type login_account: string
        :params login_password: BMC user password
        :type login_password: string
        :params destination: destination url
        :type destination: string
        :params eventtypes: event types
        :type eventtypes: list
        :params context: context of event
        :type destination: string
        :returns: returns Add event subscriptions result when succeeded or error message when failed
        """
    #check paramater
    typelist = ["StatusChange","ResourceUpdated","ResourceAdded","ResourceRemoved","Alert","MetricReport"]
    flag = False
    for type in eventtypes:
        flag = True
        if type not in typelist:
            flag = False
            break
    if flag is False:
        result = {'ret':False,'msg':"The value of event type outside the scope,please check your input"}
        return result
    result = {}
    login_host = "https://" + ip

    # Connect using the BMC address, account name, and password
    # Create a REDFISH object
    REDFISH_OBJ = redfish.redfish_client(base_url=login_host, username=login_account,
                                         password=login_password, default_prefix='/redfish/v1', cafile=utils.g_CAFILE)

    # Login into the server and create a session
    try:
        REDFISH_OBJ.login(auth=utils.g_AUTH)
    except:
        result = {'ret': False, 'msg': "Please check the username, password, IP is correct\n"}
        return result
    # Get ServiceBase resource
    try:
        # Get /redfish/v1
        response_base_url = REDFISH_OBJ.get('/redfish/v1', None)
        if response_base_url.status == 200:
            # Get /redfish/v1/EventService
            event_url = response_base_url.dict["EventService"]["@odata.id"]
            response_event_url = REDFISH_OBJ.get(event_url,None)
            if response_event_url.status == 200:
                # Check EventService Version
                EventService_Version = 130 #default version v1_3_0
                EventService_Type = response_event_url.dict["@odata.type"]
                EventService_Type = EventService_Type.split('.')[-2]
                if EventService_Type.startswith('v'):
                    EventService_Version = int(EventService_Type.replace('v','').replace('_',''))
                # Get /redfish/v1/EventService/Subscriptions
                subscriptions_url = response_event_url.dict["Subscriptions"]["@odata.id"]
                response_subscriptions_url = REDFISH_OBJ.get(subscriptions_url,None)
                if response_subscriptions_url.status == 200:
                    # Construct hearders and body to do post
                    headers = {"Content-Type": "application/json"}
                    if EventService_Version >= 130:
                        if "@Redfish.CollectionCapabilities" in response_subscriptions_url.dict:
                            parameter = {
                                 "Destination":destination,
                                 "Protocol":"Redfish"
                                }
                        else:
                            parameter = {
                                 "Destination":destination,
                                 "Context":context,
                                 "Protocol":"Redfish"
                                }
                    else:
                        parameter = {
                             "Destination":destination,
                             "EventTypes":eventtypes,
                             "Context":context,
                             "Protocol":"Redfish"
                            }
                    response_add_subscriptions = REDFISH_OBJ.post(subscriptions_url,body=parameter, headers=headers)
                    if response_add_subscriptions.status == 200 or response_add_subscriptions.status == 201:
                        rt_link = login_host + "/" + response_add_subscriptions.dict["@odata.id"]
                        id = rt_link.split("/")[-1]
                        result = {"ret":True,"msg":"Add event subscriptions successfully,subscription id is " + id + ",subscription's link is:" + rt_link}
                        return result
                    else:
                        error_message = utils.get_extended_error(response_add_subscriptions)
                        result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % (
                            subscriptions_url, response_add_subscriptions.status, error_message)}
                        return result
                else:
                    error_message = utils.get_extended_error(response_subscriptions_url)
                    result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % (
                        subscriptions_url, response_subscriptions_url.status, error_message)}
                    return result
            else:
                error_message = utils.get_extended_error(response_event_url)
                result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % (
                    event_url, response_event_url.status, error_message)}
                return result
        else:
            error_message = utils.get_extended_error(response_base_url)
            result = {'ret': False, 'msg': "Url '%s' response Error code %s\nerror_message: %s" % (
                '/redfish/v1', response_base_url.status, error_message)}
            return result
    except Exception as e:
        result = {'ret': False, 'msg': "Exception msg %s" % e}
        return result
    finally:
        try:
            REDFISH_OBJ.logout()
        except:
            pass

def add_helpmessage(argget):
    argget.add_argument('--destination', type=str, help="The new subscription's destination url you want to set",required=True)
    argget.add_argument('--eventtypes', type=str, nargs='+', default=['Alert'],
                        help="The event types you want to receive,supported eventtypes[StatusChange,ResourceUpdated,ResourceAdded,ResourceRemoved,Alert,MetricReport]")
    argget.add_argument('--context', type=str,
                        help="Specify a client-supplied string that is stored with the event destination subscription.",required=True)

def add_parameter():
    """Add event subscriptions parameter"""
    parameter_info = {}
    argget = utils.create_common_parameter_list(example_string='''
Example:
  "python add_event_subscriptions.py -i 10.10.10.10 -u USERID -p PASSW0RD --destination https://10.10.10.11 --eventtypes Alert --context test"
''')
    add_helpmessage(argget)
    args = argget.parse_args()
    parameter_info = utils.parse_parameter(args)
    parameter_info["destination"] = args.destination
    parameter_info["eventtypes"] = args.eventtypes
    parameter_info["context"] = args.context
    return parameter_info

if __name__ == '__main__':
    # Get parameters from config.ini and/or command line
    parameter_info = add_parameter()

    # Get connection info from the parameters user specified
    ip = parameter_info['ip']
    login_account = parameter_info["user"]
    login_password = parameter_info["passwd"]
    destination = parameter_info["destination"]
    eventtypes = parameter_info["eventtypes"]
    context = parameter_info["context"]

    # Add event subscriptions and check result
    result = add_event_subscriptions(ip, login_account,login_password,destination,eventtypes,context)
    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['msg'], sort_keys=True, indent=2))
    else:
        sys.stderr.write(result['msg'])
