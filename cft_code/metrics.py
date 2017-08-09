"""
/*****************************************************************************
 * Copyright (c) 2016, Palo Alto Networks. All rights reserved.              *
 *                                                                           *
 * This Software is the property of Palo Alto Networks. The Software and all *
 * accompanying documentation are copyrighted.  
                              
 *****************************************************************************/

Copyright 2016 Palo Alto Networks

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

import logging
import urllib2
import ssl
import xml.etree.ElementTree as et
import datetime
import time
import sys
import json


stackname=""
account=""
ScalingParameter=""
sqs_msg=None

sys.path.append('lib/')
import pan.asglib as lib

tag_key="PANW-NAT-STATUS"

remote=1

if remote > 0:
    import boto3
    cw_client = boto3.client('cloudwatch')
    ec2 = boto3.resource('ec2')
    ec2_client = ec2.meta.client
    lambda_client = boto3.client('lambda')

gwMgmtIp=""

firewall_cmd = {'ActiveSessions': '<show><system><state><filter>sw.mprelay.s1.dp0.stats.session</filter></state></system></show>',
                'DataPlaneBufferUtilization': '<show><system><state><filter>sw.mprelay.s1.dp0.packetbuffers</filter></state></system></show>',
                'DataPlaneCPUUtilization': '<show><system><state><filter>sys.monitor.s1.dp0.exports</filter></state></system></show>',
                'GPGatewayUtilization': '<show><system><state><filter>sw.rasmgr.resource.tunnel</filter></state></system></show>',
                'SessionUtilization': '<show><system><state><filter>sw.mprelay.s1.dp0.stats.session</filter></state></system></show>'
               }

def pan_print(s):
    if remote > 0:
        logger.info(s)
        return
    print(s)
    return

def getChassisReady(response):
    s1=response.replace('\n',"")
    s1=s1.replace(" ","")
    if s1.find("<![CDATA[no]]") > 0:
        return False
    if s1.find("<![CDATA[yes]]>") > 0:
        return True
    return False

def getJobStatus(response):
    s1=response.replace("/","")
    index=s1.find("<status>")
    list=s1.split("<status>")
    return list[1]

def getJobResult(response):
    s1=response.replace("/","")
    index=s1.find("<result>")
    list=s1.split("<result>")
    return list[2]

def getJobTfin(response):
    s1=response.replace("/","")
    index=s1.find("<tfin>")
    list=s1.split("<tfin>")
    return list[1]

def getJobProgress(response):
    s1=response.replace("/","")
    index=s1.find("<progress>")
    list=s1.split("<progress>")
    return list[1]

def getTag(instanceid):
    logger.info('Getting all the tags for instance: ' + instanceid)
    response=ec2_client.describe_tags(Filters=[{'Name': 'resource-id', 'Values': [instanceid]}])
    logger.info(response)
    for i in response['Tags']:
        if i['Key'] == tag_key:
            return i['Value']

    return None

def setTag(instanceid, value):
    ec2_client.create_tags(Resources=[instanceid], Tags=[{'Key': tag_key, 'Value': value}])
    return

def runCommand(gcontext, cmd, gwMgmtIp, api_key):
    try:
        response = urllib2.urlopen(cmd, context=gcontext, timeout=5).read()
        #pan_print("[RESPONSE] in send command: {}".format(response))
    except Exception as e:
         logger.error("[RunCommand Response Fail]: {}".format(e))
         pan_print("[RunCommand Response Fail]: {}".format(e))
         return None

    resp_header = et.fromstring(response)

    if resp_header.tag != 'response':
        logger.error("[ERROR]: didn't get a valid response from Firewall command: " + cmd)
        pan_print("[ERROR]: didn't get a valid response from Firewall")
        return None

    if resp_header.attrib['status'] == 'error':
        logger.error("[ERROR]: Got an error for the command: " + cmd)
        pan_print("[ERROR]: Got an error for the command: " + cmd)
        return None

    if resp_header.attrib['status'] == 'success':
        return response

    return None

def isChassisReady(gcontext, gwMgmtIp, api_key):
    pan_print('Checking whether Chassis is ready or not')
    cmd="<show><chassis-ready/></show>"
    fw_cmd= "https://"+gwMgmtIp+"/api/?type=op&cmd=" + cmd + "&key="+api_key
    try:
        response = runCommand(gcontext, fw_cmd, gwMgmtIp, api_key)
        if response is None:
            pan_print('Failed to run command: ' + fw_cmd)
            return False
        status=getChassisReady(response)
        if status == True:
            pan_print('Chassis is in ready state')
            return True
        else:
            pan_print('Chassis is not ready yet')

        pan_print("[RESPONSE] in send command: {}".format(response))
    except Exception as e:
         logger.error("[AutoCommit RESPONSE]: {}".format(e))

    return False

def isAutoCommit(gcontext, gwMgmtIp, api_key):
    pan_print('Checking whether AutoCommit is done or not')
    cmd="<show><jobs><id>1</id></jobs></show>"
    fw_cmd= "https://"+gwMgmtIp+"/api/?type=op&cmd=" + cmd + "&key="+api_key
    try:
        response = runCommand(gcontext, fw_cmd, gwMgmtIp, api_key)
        if response is None:
            pan_print('Failed to run command: ' + fw_cmd)
            return False
        status=getJobStatus(response)
        if status == "FIN":
            pan_print('AutoCommit is Done')
            pan_print('AutoCommit job status is : ' + getJobStatus(response))
            pan_print('AutoCommit job result is : ' + getJobResult(response))
            pan_print('AutoCommit job tfin is : ' + getJobTfin(response))
            pan_print('AutoCommit job Progress is : ' + getJobProgress(response))
            return True
        else:
            pan_print('AutoCommit is not done or over or failed')
            pan_print('AutoCommit job status is : ' + getJobStatus(response))
            pan_print('AutoCommit job result is : ' + getJobResult(response))
            pan_print('AutoCommit job tfin is : ' + getJobTfin(response))
            pan_print('AutoCommit job Progress is : ' + getJobProgress(response))

        pan_print("[RESPONSE] in send command: {}".format(response))
    except Exception as e:
         logger.error("[AutoCommit RESPONSE]: {}".format(e))

    return False

def isNatRule(gcontext, gwMgmtIp, api_key):
    pan_print('Checking whether NAT Rules were pushed or not')
    cmd="<show><jobs><id>2</id></jobs></show>"
    fw_cmd= "https://"+gwMgmtIp+"/api/?type=op&cmd=" + cmd + "&key="+api_key
    try:
        response = runCommand(gcontext, fw_cmd, gwMgmtIp, api_key)
        if response is None:
            pan_print('Failed to run command: ' + fw_cmd)
            return False
    except Exception as e:
         logger.error("[AutoCommit RESPONSE]: {}".format(e))
         return False

    if response.find("<status>FIN</status>") >= 1:
        pan_print('Nat Rule commit was Done. Good job')

    status=getJobStatus(response)
    if status != "FIN":
        pan_print('Job status is : ' + getJobStatus(response))
        pan_print('Job result is : ' + getJobResult(response))
        pan_print('Job tfin is : ' + getJobTfin(response))
        pan_print('Job Progress is : ' + getJobProgress(response))
        return False
 
    return True

def pushNatRules(gcontext, gwMgmtIp, api_key, untrust, ilb_ip, hostname):
    pan_print('Pushing NAT rule IP address')

    fw_cmd="https://"+gwMgmtIp+"/api/?type=config&action=set&key="+api_key+"&xpath=/config/devices/entry/vsys/entry/address&element=<entry%20name='AWS-NAT-ILB'><description>ILB-IP-address</description><ip-netmask>"+ilb_ip+"</ip-netmask></entry>"
    try:
        response = runCommand(gcontext, fw_cmd, gwMgmtIp, api_key)
        if response is None:
            pan_print('AWS-NAT-ILB: Failed to run command: ' + fw_cmd)
            return False
    except Exception as e:
         #logger.error("[NAT Address RESPONSE]: {}".format(e))
         pan_print("[NAT Address RESPONSE]: {}".format(e))
         return False

    logger.info('Untrust: ' + str(untrust))
    logger.info('gwMgmtIp: ' + str(gwMgmtIp))
    fw_cmd="https://"+gwMgmtIp+"/api/?type=config&action=set&key="+api_key+"&xpath=/config/devices/entry/vsys/entry/address&element=<entry%20name='AWS-NAT-UNTRUST'><description>UNTRUST-IP-address</description><ip-netmask>"+untrust+"</ip-netmask></entry>"
    try:
        response = runCommand(gcontext, fw_cmd, gwMgmtIp, api_key)
        if response is None:
            pan_print('AWS-NAT-ILB: Failed to run command: ' + fw_cmd)
            return False
    except Exception as e:
         #logger.error("[NAT Address RESPONSE]: {}".format(e))
         pan_print("[NAT Address RESPONSE]: {}".format(e))
         return False

    if hostname == "":
        hostname="PA-VM"

    fw_cmd="https://"+gwMgmtIp+"/api/?type=config&action=set&key="+api_key+"&xpath=/config/devices/entry[@name='localhost.localdomain']/deviceconfig/system&element=<hostname>"+hostname+"-"+gwMgmtIp+"</hostname>"
    try:
        response = runCommand(gcontext, fw_cmd, gwMgmtIp, api_key)
        if response is None:
            logger.error('AWS-NAT-ILB: Hostname Failed to run command: ' + fw_cmd)
    except Exception as e:
         logger.error("[HostName RESPONSE]: {}".format(e))
         return False

    fw_cmd="https://"+gwMgmtIp+"/api/?type=config&action=set&key="+api_key+"&xpath=/config/devices/entry[@name='localhost.localdomain']/deviceconfig/system&element=<server-verification>yes</server-verification>"
    try:
        response = runCommand(gcontext, fw_cmd, gwMgmtIp, api_key)
        if response is None:
            logger.error('AWS-NAT-ILB: API server-verification failed: ' + fw_cmd)
    except Exception as e:
         logger.error("[server-verification RESPONSE]: {}".format(e))
         return False

    fw_cmd="https://"+gwMgmtIp+"/api/?type=commit&cmd=<commit></commit>&key="+api_key
    try:
        response = runCommand(gcontext, fw_cmd, gwMgmtIp, api_key)
        if response is None:
            pan_print('Commit: Failed to run command: ' + fw_cmd)
            return False
    except Exception as e:
         #logger.error("[Commit RESPONSE]: {}".format(e))
         pan_print("[Commit RESPONSE]: {}".format(e))
         return False

    return True

def getUntrustIP(instanceid, untrust):
    logger.info('Getting IP address of Untrust Interface for instance: ' + instanceid)
    ip=""
    found=False
    response=ec2_client.describe_instances(InstanceIds=[instanceid])
    logger.info(response)
    for r in response['Reservations']:
        for i in r['Instances']:
            for s in i['NetworkInterfaces']:
                 if s['SubnetId'] == untrust:
                     found=True
                     ip=s['PrivateIpAddress']
                     break

        if found == True:
            break

    if found == True:
        return ip

    return None


def valueToDict(v, s):
    d={}
    try:
        str= v.replace(s, "")
        str=str.replace("'", "\"")
        str=str.replace(", }", "}")
        d = json.loads(str)
        pan_print(json.dumps(d, indent=4))
    except Exception as e:
         logger.error("[valueToDict]: {}".format(e))
         pan_print("[valueToDict]: {}".format(e))
         return None

    return d

def valueToString(v, s):
    str=""
    try:
        str= v.replace(s, "")
        str=str.replace("'", "\"")
        str=str.replace(", }", "")
        str=str.replace('\n', "")
        str=str.replace(',', "")
        pan_print(str)
    except Exception as e:
         logger.error("[valueToDict]: {}".format(e))
         pan_print("[valueToDict]: {}".format(e))
         return None

    return str

def ActiveSessions(root, namespace, asg_name):
    #Now to find number of active sessions
    logger.info('ActiveSessions...');
    logger.info('root[0][1].text: ' + str(root[0].text))
    value=""
    d=valueToDict(str(root[0].text), "sw.mprelay.s1.dp0.stats.session:")
    if d is None:
        pan_print('Error happened in ActiveSessions: ' + str(root[0].text))
        return

    value=float(d['session_active'])
    pan_print('ActiveSessions in numbers: ' + str(value))

    if remote == 0:
        return

    if sqs_msg is not None:
        v=lib.getScalingValue(sqs_msg, ScalingParameter)
        if v is not None:
            print(sqs_msg)
            logger.info('Pushing simulated data to CW: ' + str(v))
            value=float(v)
        else:
            logger.info('Starting to Publish metrics in namespace: ' + namespace)
    else:
        logger.info('Starting to Publish metrics in namespace: ' + namespace)

    timestamp = datetime.datetime.utcnow()
    response = cw_client.put_metric_data(
                Namespace=namespace,
                MetricData=[{
                        'MetricName': 'ActiveSessions',
                        'Dimensions':[{
                                'Name': 'AutoScalingGroupName',
                                'Value': asg_name
                            }],
                        'Timestamp': timestamp,
                        'Value': value,
                        'Unit': 'Count'
                    }]
    )

    logger.info("[INFO]: Published GOOD metric for {}".format(gwMgmtIp))
    return

def DataPlaneCPUUtilization(root, namespace, asg_name):
    logger.info('DataPlaneCPUUtilization');
    logger.info('root[0][1].text: ' + str(root[0].text))
    cpu=""
    d=valueToDict(str(root[0].text), "sys.monitor.s1.dp0.exports:")
    if d is None:
        pan_print('Error happened in DataPlaneCPUUtilization: ' + str(root[0].text))
        return

    cpu=float(d['cpu']['1minavg'])
    pan_print('DataPlaneCPUUtilization in percentage: ' + str(cpu))

    if remote == 0:
        return

    if sqs_msg is not None:
        v=lib.getScalingValue(sqs_msg, ScalingParameter)
        if v is not None:
            print(sqs_msg)
            logger.info('Pushing simulated data to CW: ' + str(v))
            cpu=float(v)
        else:
            logger.info('Starting to Publish metrics in namespace: ' + namespace)
    else:
        logger.info('Starting to Publish metrics in namespace: ' + namespace)

    timestamp = datetime.datetime.utcnow()
    response = cw_client.put_metric_data(
                Namespace=namespace,
                MetricData=[{
                        'MetricName': 'DataPlaneCPUUtilization',
                        'Dimensions':[{
                                'Name': 'AutoScalingGroupName',
                                'Value': asg_name
                            }],
                        'Timestamp': timestamp,
                        'Value': cpu,
                        'Unit': 'Percent'
                    }]
    )

    logger.info("[INFO]: Published GOOD metric for {}".format(gwMgmtIp))
    return

def DataPlaneBufferUtilization(root, namespace, asg_name):
    logger.info('DataPlaneBufferUtilization...');
    logger.info('root[0][1].text: ' + str(root[0].text))

    hw_buf=str(root[0].text)
    hw_buf=hw_buf.replace("hardware buffer", '"hardware buffer"')
    hw_buf=hw_buf.replace("packet descriptor", '"packet descriptor"')
    hw_buf=hw_buf.replace("software buffer", '"software buffer"')
    d=valueToDict(hw_buf, "sw.mprelay.s1.dp0.packetbuffers:")
    if d is None:
        pan_print('Error happened in DataPlaneBufferUtilization: ' + str(root[0].text))
        return
   
    pan_print('Get is: ' + str(d.get('hw-buf')))
    max=str(d['hw-buf']['max'])
    used=str(d['hw-buf']['used'])
    m=float(max)
    u=float(used)
    v=(u/m) * 100
    value=float("{0:.2f}".format(v))
    pan_print('DataPlaneBufferUtilization in percentage: Max: ' + max + ' Used: ' + used +  ' Util: ' + str(value))

    if remote == 0:
        return

    if sqs_msg is not None:
        v=lib.getScalingValue(sqs_msg, ScalingParameter)
        if v is not None:
            print(sqs_msg)
            logger.info('Pushing simulated data to CW: ' + str(v))
            value=float(v)
        else:
            logger.info('Starting to Publish metrics in namespace: ' + namespace)
    else:
        logger.info('Starting to Publish metrics in namespace: ' + namespace)

    timestamp = datetime.datetime.utcnow()
    response = cw_client.put_metric_data(
                Namespace=namespace,
                MetricData=[{
                        'MetricName': 'DataPlaneBufferUtilization',
                        'Dimensions':[{
                                'Name': 'AutoScalingGroupName',
                                'Value': asg_name
                            }],
                        'Timestamp': timestamp,
                        'Value': value,
                        'Unit': 'Percent'
                    }]
    )

    logger.info("[INFO]: Published GOOD metric for {}".format(gwMgmtIp))
    return

def GPActiveTunnels(root, namespace, asg_name):
    pan_print('Not Supported')
    return

def GPGatewayUtilization(root, namespace, asg_name):
    logger.info('GPGatewayUtilization...');
    logger.info('root[0][1].text: ' + str(root[0].text))
    d=valueToString(str(root[0].text), "sw.rasmgr.resource.tunnel:")
    if d is None:
        pan_print('Error happened in DataPlaneBufferUtilization: ' + str(root[0].text))
        return

    list=d.split(" ")
    cur=list[3]
    max=list[5]

    cur=str(int(cur, 16))
    max=str(int(max, 16))

    m=float(max)
    u=float(cur)
    v=(u/m) * 100
    value=float("{0:.2f}".format(v))
    pan_print('GPGatewayUtilization in percentage: Max: ' + max + ' Cur: ' + cur +  ' Util: ' + str(value))

    if remote == 0:
        return

    if sqs_msg is not None:
        v=lib.getScalingValue(sqs_msg, ScalingParameter)
        if v is not None:
            print(sqs_msg)
            logger.info('Pushing simulated data to CW: ' + str(v))
            value=float(v)
        else:
            logger.info('Starting to Publish metrics in namespace: ' + namespace)
    else:
        logger.info('Starting to Publish metrics in namespace: ' + namespace)

    timestamp = datetime.datetime.utcnow()
    response = cw_client.put_metric_data(
                Namespace=namespace,
                MetricData=[{
                        'MetricName': 'GPGatewayUtilization',
                        'Dimensions':[{
                                'Name': 'AutoScalingGroupName',
                                'Value': asg_name
                            }],
                        'Timestamp': timestamp,
                        'Value': value,
                        'Unit': 'Percent'
                    }]
    )

    logger.info("[INFO]: Published GOOD metric for {}".format(gwMgmtIp))
    return

def SessionUtilization(root, namespace, asg_name):
    logger.info('SessionUtilization');
    logger.info('root[0][1].text: ' + str(root[0].text))
    sess=0.0
    d=valueToDict(str(root[0].text), "sw.mprelay.s1.dp0.stats.session:")
    if d is None:
        pan_print('Error happened in SessionUtilization: ' + str(root[0].text))
        return

    sess=float(d['session_util'])
    pan_print('SessionUtilization in percentage: ' + str(sess))

    if remote == 0:
        return

    if sqs_msg is not None:
        v=lib.getScalingValue(sqs_msg, ScalingParameter)
        if v is not None:
            print(sqs_msg)
            logger.info('Pushing simulated data to CW: ' + str(v))
            sess=float(v)
        else:
            logger.info('Starting to Publish metrics in namespace: ' + namespace)
    else:
        logger.info('Starting to Publish metrics in namespace: ' + namespace)

    timestamp = datetime.datetime.utcnow()
    response = cw_client.put_metric_data(
                Namespace=namespace,
                MetricData=[{
                        'MetricName': 'SessionUtilization',
                        'Dimensions':[{
                                'Name': 'AutoScalingGroupName',
                                'Value': asg_name
                            }],
                        'Timestamp': timestamp,
                        'Value': sess,
                        'Unit': 'Percent'
                    }]
    )

    logger.info("[INFO]: Published GOOD metric for {}".format(gwMgmtIp))
    return

cw_func_metrics = { 'DataPlaneCPUUtilization': DataPlaneCPUUtilization,
                        'ActiveSessions': ActiveSessions,
                        'SessionUtilization': SessionUtilization,
                        'GPGatewayUtilization': GPGatewayUtilization,
                        'GPActiveTunnels': GPActiveTunnels,
                        'DataPlaneBufferUtilization': DataPlaneBufferUtilization}


def lambda_handler(event, context):
    global gwMgmtIp
    global logger
    global stackname
    global account
    global sqs_msg
    global ScalingParameter

    #logger = logging.getLogger()
    

    #print(event)
    stackname=event['StackName']
    Namespace=event['Namespace']
    KeyPANWFirewall=event['KeyPANWFirewall']
    KeyPANWPanorama=event['KeyPANWPanorama']
    ScalingParameter=event['ScalingParameter']
    api_key=event['KeyPANWFirewall']
    instanceid=event['EC2InstanceId']
    ilb_ip=event['ILBIPAddress']
    untrust_subnet=event['UntrustSubnet']
    hostname=event['Hostname']

    logger = logging.getLogger()
    #logger.setLevel(logging.DEBUG)
    account=event['Arn']
    sqs_msg=lib.getSqsMessages(stackname, account)
    if sqs_msg is not None:
        lvl=lib.getDebugLevelFromMsg(sqs_msg)
        if lvl is not None:
            lib.setDebugLevelFromMsg(logger, lvl)

    try:
        asg_name = event.get('ASGName')
        lfunc=lib.get_lambda_cloud_watch_func_name(stackname, asg_name, instanceid)
        lresponse=lambda_client.get_function(FunctionName=lfunc)
        logger.info(json.dumps(lresponse))
    except Exception as e:
        logger.info("Error getting lambda function name")

    logger.info('got event{}'.format(event))
    logger.info('StackName: ' + event['StackName'] +  ' FW IP: ' + event['FWIP'] + ' SP: ' + ScalingParameter + ' NameSpace: ' + Namespace)

    # In case if instance is no longer there, we should remove ourself
    remove=False
    try:
        response=ec2_client.describe_instance_status(InstanceIds=[instanceid])
        status=response['InstanceStatuses']
        if len(status) == 0:
            remove=True
    except Exception as e:
        logger.error("[InstanceNotFound]: {}".format(e))
        remove=True

    if remove == True:
        logger.info('Instance ID: ' + instanceid + ' not FOUND')
        PIP=event['PIP']
        PDG=event['PDG']
        PTPL=event['PTPL']
        if PIP != "":
            for i in range(1,250):
                tr=context.get_remaining_time_in_millis()
                if tr < 15000:
                    logger.error('Exiting CloudWatch Lambda without removing instance/firewall from Panorama. InstaceId: ' + str(instanceid))
                    break

                try:
                    if lib.remove_fw_from_panorama(stackname, instanceid, KeyPANWPanorama, event.get('FWPIP'), PIP, PDG, PTPL) == False:
                        logger.error('Device can not be removed from Panorama at this time. We will retry after a minute')
                    else:
                        break
                except Exception as e:
                    logger.error("[Remove FW From Panorama CloudWatch Lambda]: {}".format(e))
                    logger.error('Not removing this lambda because of failure. We will retry after a minute')
                time.sleep(1)

        asg_name = event.get('ASGName')
        lib.delete_cw_metrics_lambda(stackname, asg_name, instanceid, None)
        return

    gwMgmtIp = event.get('FWIP')
    if gwMgmtIp == None:
        logger.error("[ERROR]: Didn't get GW MGMT IP in event")
        return

    asg_name = event.get('ASGName')
    if asg_name == None:
        logger.error("[ERROR]: Didn't get auto scaling group name in event")
        return

    # Need this to by pass invalid certificate issue.
    gcontext = lib.get_ssl_context()

    value=getTag(instanceid)
    if value is None:
        if isChassisReady(gcontext, gwMgmtIp, api_key) == False:
            logger.info('Chassis is not in ready state yet')
            isAutoCommit(gcontext, gwMgmtIp, api_key)
            return

        untrust=getUntrustIP(instanceid, untrust_subnet)
        if pushNatRules(gcontext, gwMgmtIp, api_key, untrust, ilb_ip, hostname) == False:
            logger.error('Unable to push NAT IP address');
            setTag(instanceid, "NatCommitFailure")
            return
        else:
            setTag(instanceid, "NatCommitSuccess")
    elif value != "NatCommitSuccess":
        untrust=getUntrustIP(instanceid, untrust_subnet)
        if pushNatRules(gcontext, gwMgmtIp, api_key, untrust, ilb_ip, hostname) == False:
            logger.error('Unable to push NAT IP address');
            setTag(instanceid, "NatCommitFailure")
            return
        else:
            setTag(instanceid, "NatCommitSuccess")
        
    logger.info('Instance Tag state is : ' + str(value))

    cmd = firewall_cmd[ScalingParameter]
    fw_cmd = "https://"+gwMgmtIp+"/api/?type=op&cmd=" + cmd + "&key="+api_key
    logger.info('[INFO]: Sending API command : %s', fw_cmd)
    try:
        response = urllib2.urlopen(fw_cmd, context=gcontext, timeout=5).read()
        logger.debug("[RESPONSE] in send command: {}".format(response))
    except Exception as e:
         logger.error("[ERROR]: Something bad happened when sending command")
         logger.error("[RESPONSE]: {}".format(e))
         return
    else:
        logger.info("[INFO]: Got a response from command urlopen")

    resp_header = et.fromstring(response)

    if resp_header.tag != 'response':
        logger.error("[ERROR]: didn't get a valid response from GW")
        return

    if resp_header.attrib['status'] == 'error':
        logger.error("[ERROR]: Got an error for the command")
        return

    if resp_header.attrib['status'] == 'success':
        logger.info("[INFO]: Successfully executed command urlopen. Now publish metrics")
        cw_func_metrics[ScalingParameter](resp_header, Namespace, asg_name)


def test():
    pan_print('Local Test Start...........')
    ScalingParameter="DataPlaneCPUUtilization"
    ScalingParameter="ActiveSessions"
    ScalingParameter="DataPlaneBufferUtilization"
    ScalingParameter="SessionUtilization"
    ScalingParameter="GPGatewayUtilization"
    ScalingParameter="DataPlaneBufferUtilization"
    Namespace="panw"
    asg_name="test-asg"
    gwMgmtIp="10.4.20.90"
    untrust="1.1.1.1"
    ilb_ip="2.2.2.2"

    api_key = "LUFRPT14MW5xOEo1R09KVlBZNnpnemh0VHRBOWl6TGM9bXcwM3JHUGVhRlNiY0dCR0srNERUQT09"

    # Need this to by pass invalid certificate issue. Should try to fix this
    gcontext = get_ssl_context()

    if isChassisReady(gcontext, gwMgmtIp, api_key) == False:
        pan_print('Chassis is not ready yet')
        return

    cmd = firewall_cmd[ScalingParameter]
    fw_cmd = "https://"+gwMgmtIp+"/api/?type=op&cmd=" + cmd + "&key="+api_key
    logger.info('[INFO]: Sending API command : %s', fw_cmd)
    try:
        response = urllib2.urlopen(fw_cmd, context=gcontext, timeout=5).read()
        logger.info("[RESPONSE] in send command: {}".format(response))
    except Exception as e:
         logger.error("[ERROR]: Something bad happened when sending command")
         logger.error("[RESPONSE]: {}".format(e))
         return
    else:
        logger.info("[INFO]: Got a response from command urlopen")

    resp_header = et.fromstring(response)

    if resp_header.tag != 'response':
        logger.error("[ERROR]: didn't get a valid response from GW")
        return

    if resp_header.attrib['status'] == 'error':
        logger.error("[ERROR]: Got an error for the command")
        return

    if resp_header.attrib['status'] == 'success':
        #The fw responded with a successful command execution.
        logger.info("[INFO]: Successfully executed command urlopen. Now publish metrics")
        pan_print(response)
        cw_func_metrics[ScalingParameter](resp_header, Namespace, asg_name)

if remote == 0:
    test()
