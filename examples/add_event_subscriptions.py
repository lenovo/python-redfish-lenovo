###
#
# Lenovo Redfish examples - Add event subscriptions
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

def add_event_subscriptions(ip, login_account, login_password, destination, subscribe_type='Event', context='', protocol='Redfish'):
    """Add event subscriptions
        :params ip: BMC IP address
        :type ip: string
        :params login_account: BMC user name
        :type login_account: string
        :params login_password: BMC user password
        :type login_password: string
        :params destination: destination url
        :type destination: string
        :params subscribe_type: subscribe event format type
        :type subscribe_type: string
        :params context: context of event
        :type destination: string
        :params context: protocol of destination
        :type destination: string
        :returns: returns Add event subscriptions result when succeeded or error message when failed
        """
    result = {}
    login_host = "https://" + ip

    # Connect using the BMC address, account name, and password
    # Create a REDFISH object
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
                response_subscriptions_url = REDFISH_OBJ.get(subscriptions_url, None)
                if response_subscriptions_url.status == 200:
                    # Construct hearders and body to do post
                    headers = {"Content-Type": "application/json"}
                    if EventService_Version >= 160 and protocol == 'SMTP':
                        if '@' not in destination:
                            result = {'ret': False, 'msg': 'mail address %s is invalid, please correct it first.' %destination}
                            return result
                        parameter = {
                                "Destination": "mailto:%s" %(destination),
                                "Protocol": protocol
                                }
                    elif EventService_Version >= 160 and protocol == 'SNMPv1':
                        parameter = {
                                "Destination": "snmp://%s" %(destination),
                                "Protocol": protocol
                                }
                    elif EventService_Version >= 160 and protocol == 'SNMPv3':
                        if '@' not in destination:
                            result = {'ret': False, 'msg': 'SNMPv3 address %s is invalid, please correct it first.' %destination}
                            return result
                        parameter = {
                                "Destination": "snmp://%s" %(destination),
                                "Protocol": protocol
                                }
                    elif EventService_Version >= 160 and protocol == 'Redfish':

                        if subscribe_type == 'MetricReport':
                            parameter = {
                                 "Destination": destination,
                                 "Protocol": "Redfish",
                                 "SubscriptionType": "RedfishEvent",
                                 "EventFormatType": "MetricReport",
                                }
                            # Additional filter to configure on create
                            # "MetricReportDefinitions": [],  filter by Metric Report Definitions, if not set, subscribe all
                        else:
                            parameter = {
                                 "Destination": destination,
                                 "Protocol": "Redfish",
                                 "SubscriptionType": "RedfishEvent",
                                 "EventFormatType": "Event",
                                }
                            # Additional filter to configure on create
                            # "MessageIds": [],             filter by Message Ids, if not set, subscribe all
                            # "RegistryPrefixes": [],       filter by Registry Prefixes, if not set, subscribe all
                            # "ResourceTypes": [],          filter by Resource Types, if not set, subscribe all
                            # "OriginResources": [],        filter by Origin Resources, if not set, subscribe all
                            # "SubordinateResources": True, indicate whether the subscription is for events in the OriginResources array and its subordinate Resources
                        if context is not None and context != '':
                            parameter['Context'] = context

                    elif EventService_Version < 160 and protocol != 'Redfish':
                        result = {'ret': False, 'msg': 'Target server only support Redfish protocol.'}
                        return result

                    elif EventService_Version >= 130:
                        if "@Redfish.CollectionCapabilities" in response_subscriptions_url.dict:
                            parameter = {
                                 "Destination":destination,
                                 "Protocol":"Redfish"
                                }
                        else:
                            parameter = {
                                 "Destination":destination,
                                 "Protocol":"Redfish"
                                }
                            if context is not None and context != '':
                                parameter['Context'] = context
                    else:
                        parameter = {
                             "Destination":destination,
                             "Protocol":"Redfish"
                            }
                        if context is not None and context != '':
                            parameter['Context'] = context
                        if subscribe_type == 'Event':
                            eventtypes = ['StatusChange', 'ResourceUpdated', 'ResourceAdded', 'ResourceRemoved', 'Alert']
                        else:
                            eventtypes = ['MetricReport']
                        parameter['EventTypes'] = eventtypes

                    # Perform post to create new subscription
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
        traceback.print_exc()
        result = {'ret': False, 'msg': "Exception msg %s" % e}
        return result
    finally:
        try:
            REDFISH_OBJ.logout()
        except:
            pass


def add_helpmessage(argget):
    argget.add_argument('--protocol', type=str, default='Redfish', choices=['Redfish', 'SMTP', 'SNMPv1', 'SNMPv3'],
                        help="Specify the protocol of new subscription's destination. Default value is Redfish.")
    argget.add_argument('--destination', required=True, type=str,
                        help="Specify the new subscription's destination url you want to set. If protocol is Redfish, destination format should be like 'https://10.10.10.11'. If protocol is SMTP, destination format should be like 'myname@example.com'. If protocol is SNMPv1, destination format should be like '10.10.10.11'. If protocol is SNMPv3, destination format should be like 'USERID@10.10.10.11'")
    argget.add_argument('--subscribe_type', type=str, default='Event', choices=['Event', 'MetricReport'],
                        help="Specify Event or MetricReport which you want to subscribe. Default value is Event. This option is only for Redfish protocol.")
    # As EventTypes property has been deprecated, depercate this parameter too
    #argget.add_argument('--eventtypes', type=str, nargs='+', default=['Alert'],
    #                    help="The event types you want to receive,supported eventtypes[StatusChange,ResourceUpdated,ResourceAdded,ResourceRemoved,Alert,MetricReport]")
    argget.add_argument('--context', type=str, default='',
                        help="Specify a client-supplied string that is stored with the event destination subscription. This option is only for Redfish protocol.")


def add_parameter():
    """Add event subscriptions parameter"""
    parameter_info = {}
    argget = utils.create_common_parameter_list(example_string='''
Example:
  "python add_event_subscriptions.py -i 10.10.10.10 -u USERID -p PASSW0RD --destination https://10.10.10.11 --context test"
''')
    add_helpmessage(argget)
    args = argget.parse_args()
    parameter_info = utils.parse_parameter(args)
    parameter_info["destination"] = args.destination
    parameter_info["subscribe_type"] = args.subscribe_type
    parameter_info["context"] = args.context
    parameter_info["protocol"] = args.protocol
    return parameter_info

if __name__ == '__main__':
    # Get parameters from config.ini and/or command line
    parameter_info = add_parameter()

    # Get connection info from the parameters user specified
    ip = parameter_info['ip']
    login_account = parameter_info["user"]
    login_password = parameter_info["passwd"]
    destination = parameter_info["destination"]
    subscribe_type = parameter_info["subscribe_type"]
    context = parameter_info["context"]
    protocol = parameter_info["protocol"]

    # Add event subscriptions and check result
    result = add_event_subscriptions(ip, login_account, login_password, destination, subscribe_type, context, protocol)
    if result['ret'] is True:
        del result['ret']
        sys.stdout.write(json.dumps(result['msg'], sort_keys=True, indent=2))
    else:
        sys.stderr.write(result['msg'])
