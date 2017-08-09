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

import boto3
import logging
import json
import httplib
import xml.etree.ElementTree as et
import time
from urlparse import urlparse
from contextlib import closing
import ssl
import urllib2
import decimal
import uuid
import sys
import urllib
import hashlib
import base64

sys.path.append('lib/')
import pan.asglib as lib

s3 = boto3.client('s3')
ec2 = boto3.resource('ec2')
ec2_client = ec2.meta.client
lambda_client = boto3.client('lambda')
iam = boto3.client('iam')
events_client = boto3.client('events')
elb = boto3.client('elb')
asg = boto3.client('autoscaling')
cloudwatch = boto3.client('cloudwatch')

logger = logging.getLogger()
logger.setLevel(logging.INFO)

valid_panfw_productcode_ids = {
    "6njl1pau431dv1qxipg63mvah": "VMLIC_BYOL",
    "ezf1psxb2kioq7658vhqcsd8l": "VM100_BND1",
    "aq69x88mwu3gsgzl9cnp2jrs" : "VM100_BND2",
    "6mydlutex4aol2trr2g7q65iv": "VM200_BND1",
    "1a8cei9n1136q07w76k0hsryu": "VM200_BND2",
    "6kxdw3bbmdeda3o6i1ggqt4km": "VM300_BND1",
    "806j2of0qy5osgjjixq9gqc6g": "VM300_BND2",
    "drl1fmzuqe2xzolduol1a44lk": "VM1000_BND1",
    "2yxza6dt6eedvvs80ohu1ae63": "VM1000_BND2",
    #AWS IC product codes
    "3bgub3avj7bew2l8odml3cxdx": "VMLIC_IC_BYOL",
    "atpzu21quydhsik27m2f0u8f" : "VM300_IC_BND1",
    "13w0cso64r7c4rralytfju3p6": "VM300_IC_BND2"
}


def random_string(string_length=10):
    """
    
    :param string_length: 
    :return: 
    """
    random = str(uuid.uuid4()) 
    random = random.replace("-","") 
    return random[0:string_length]

def send_response(event, context, responseStatus):
    """
    Method to send a response back to the CFT process.
    
    :param event: 
    :param context: 
    :param responseStatus: 
    :return: 
    """
    r=responseStatus.split(":")
    print(r)
    rs=str(r[0])
    reason=""
    if len(r) > 1:
        reason = str(r[1])
    else:
        reason = 'See the details in CloudWatch Log Stream.'
    print('send_response() to stack -- responseStatus: ' + str(rs) + ' Reason: ' + str(reason))
    response = {
                'Status': str(rs),
                'Reason': str(reason),
                'StackId': event['StackId'],
                'RequestId': event['RequestId'],
                'LogicalResourceId': event['LogicalResourceId'],
                'PhysicalResourceId': event['LogicalResourceId']
               }
    logger.info('RESPONSE: ' + json.dumps(response))
    parsed_url = urlparse(event['ResponseURL'])
    if (parsed_url.hostname == ''):
        logger.info('[ERROR]: Parsed URL is invalid...')
        return 'false'

    logger.info('[INFO]: Sending Response...')
    try:
        with closing(httplib.HTTPSConnection(parsed_url.hostname)) as connection:
            connection.request("PUT", parsed_url.path+"?"+parsed_url.query, json.dumps(response))
            response = connection.getresponse()
            if response.status != 200:
                logger.info('[ERROR]: Received non 200 response when sending response to cloudformation')
                logger.info('[RESPONSE]: ' + response.msg)
                return 'false'
            else:
                logger.info('[INFO]: Got good response')

    except:
        logger.info('[ERROR]: Got ERROR in sending response...')
        return 'false'
    finally:

        connection.close()
        return 'true'

def get_event_rule_name(stackname):
    """
    Method to create a unique name for the 
    event rules. 
    
    .. note:: The event name is constructed by appending 
              a fixed string to the stack name.
    :param stackname: 
    :return: 
    """
    name = stackname + 'event-rule-init-lambda'
    return name[-63:len(name)]
    
def get_target_id_name(stackname):
    """
    
    :param stackname: 
    :return: 
    """
    name = stackname + 'target-id-init-lambda'
    return name[-63:len(name)]

def no_asgs(elbname):
    """
    
    :param elbname: 
    :return: 
    """
    asg_response=asg.describe_auto_scaling_groups()
    found = False
    for i in asg_response['AutoScalingGroups']:
        logger.info('ASG i[AutoScalingGroupName]: ' + i['AutoScalingGroupName'])
        for lbn in i['LoadBalancerNames']:
            if lbn == elbname:
                asg_name = i['AutoScalingGroupName']
                found = True
    return found

def read_s3_object(bucket, key):
    """
    Method to read data from and S3 bucket.
    
    .. note:: This method is used to read bootstrap 
              information, in order to license and 
              configure the firewall.
    
    :param bucket: 
    :param key: 
    :return: 
    """
    # Get the object from the event and show its content type
    key = urllib.unquote_plus(key).decode('utf8')
    try:
        response = s3.get_object(Bucket=bucket, Key=key)
        print("CONTENT TYPE: " + response['ContentType'])
        contents=response['Body'].read()
        #print('Body: ' + str(contents))
        return str(contents)
    except Exception as e:
        print(e)
        print('Error getting object {} from bucket {}. Make sure they exist.'.format(key, bucket))
        return None

def get_panorama_ip(contents):
    """
    
    :param contents: 
    :return: 
    """
    contents=contents.replace('\n', '::')
    list=contents.split("::")
    for i in list:
        if i == "":
            continue

        s=i.split("=")
        if s[0] != "" and s[0] == "panorama-server" and s[1] != "":
            return s[1]
    print('Panorama IP not found')
    return None

def delete_load_balancers(r):
    """
    
    :param r: 
    :return: 
    """
    logger.info('Deleting Load Balancers...')
    try:
        elb.delete_load_balancer(LoadBalancerName=r['ELBName'])
    except Exception as e:
        logger.error("[Delete LB]: {}".format(e))

    err = lib.delete_load_balancer(r['ILBName'])
    if err == 'FAIL':
        logger.error("Delete ILB FAILED")

def remove_sched_func(stackname):
    """
    Remove the sched_evt function, in order to 
    cleanup when the CFT stack is deleted. 
    
    :param stackname: 
    :return: 
    """
    lambda_func_name= stackname + '-lambda-sched-event'
    event_rule_name= get_event_rule_name(stackname)
    target_id_name = get_target_id_name(stackname)
    try:
        events_client.remove_targets(Rule=event_rule_name,
                    Ids=[target_id_name])
    except Exception as e:
        logger.error("[Remove Targets]: {}".format(e))

    logger.info('Deleting event rule: ' +  event_rule_name)
    try:
        events_client.delete_rule(Name=event_rule_name)
    except Exception as e:
        logger.error("[Delete Rule]: {}".format(e))

    logger.info('Delete lambda function: ' + lambda_func_name)
    try:
        lambda_client.delete_function(FunctionName=lambda_func_name)
        return True
    except Exception as e:
        logger.error("[Delete Lambda Function]: {}".format(e))

    return False


def delete_resources(event):
    """
    Method to handle the delete of resources when the 
    CFT stack is deleted. 
    
    :param event: 
    :return: 
    """
    logger.info('Deleteing resources...')
    stackname = event['ResourceProperties']['StackName']

    r = event['ResourceProperties']
    logger.info('Dump all the parameters')
    logger.info(r)
    ILBName = r['ILBName']
    ELBName = r['ELBName']
    ScalingParameter = r['ScalingParameter']
    KeyPANWPanorama = r['KeyPANWPanorama']
    MasterS3Bucket = r['MasterS3Bucket']

    remove_sched_func(stackname)
    #if r['LoadBalancer'] == "Yes":
    #    delete_load_balancers(r)

    lib.delete_asg_stacks(stackname, r, ILBName, ELBName, ScalingParameter, KeyPANWPanorama)
    return

def subnetToList(listoflist):
    """
    
    :param listoflist: 
    :return: 
    """
    d_temp = []
    for l in listoflist:
        d_temp.append(l.encode('ascii'))
    print(d_temp)
    return d_temp



#DUMMY FUNC -- NOT USED
def create_load_balancers(r):
    """
    This function is not used.
    :param r: 
    :return: 
    """
    if r['LoadBalancer'] == "No":
        return True

    logger.info('Creating ELB: ' + r['ELBName'] + ' ILB: ' + r['ILBName'])
    SubnetIDTrust = subnetToList(r['SubnetIDTrust'])
    SubnetIDUntrust = subnetToList(r['SubnetIDUntrust'])
    logger.info(SubnetIDTrust)
    logger.info(SubnetIDUntrust)
    PublicLoadBalancerSecurityGroup=r['PublicLoadBalancerSecurityGroup']
    PrivateLoadBalancerSecurityGroup=r['PrivateLoadBalancerSecurityGroup']

    try:
        elb.create_load_balancer(LoadBalancerName=r['ELBName'],
		Listeners=[{'Protocol': 'HTTP', 'LoadBalancerPort': 80, 'InstancePort': 80}],
		Subnets=SubnetIDUntrust,
		SecurityGroups=[PublicLoadBalancerSecurityGroup])

        elb.configure_health_check(LoadBalancerName=r['ELBName'],
		HealthCheck={
          	   'Target' : 'HTTP:80/index.html',
                   'HealthyThreshold' : 3,
                   'UnhealthyThreshold' : 5,
                   'Interval' : 30,
                   'Timeout' : 5
		})

        elb.create_load_balancer(LoadBalancerName=r['ILBName'],
		Listeners=[{'Protocol': 'HTTP', 'LoadBalancerPort': 80, 'InstancePort': 80}],
		Subnets=SubnetIDTrust,
                Scheme='internal',
		SecurityGroups=[PrivateLoadBalancerSecurityGroup])

        elb.configure_health_check(LoadBalancerName=r['ILBName'],
		HealthCheck={
          	   'Target' : 'HTTP:80/index.html',
                   'HealthyThreshold' : 3,
                   'UnhealthyThreshold' : 5,
                   'Interval' : 30,
                   'Timeout' : 5
		})
    except:
        logger.info('[Create LB]: Got ERROR in sending response...')
        return False

    return True

def common_alarm_func_update(asg_name, metricname, namespace, arn_scalein, arn_scaleout, alarmname, desc):
    """
    Method to create alarms to be monitored on instances in an ASG
    :param asg_name: 
    :param metricname: 
    :param namespace: 
    :param arn_scalein: 
    :param arn_scaleout: 
    :param alarmname: 
    :param desc: 
    :return: 
    """
    d1=desc+ " High"
    a1=alarmname + '-high'
    try:
        cloudwatch.put_metric_alarm(AlarmName=a1, AlarmDescription=d1,
            AlarmActions=[arn_scaleout],
            ActionsEnabled=True, MetricName=metricname, EvaluationPeriods=1,
            Threshold=float(ScaleUpThreshold), Statistic="Average", Namespace=namespace,
            Dimensions=[{'Name': "AutoScalingGroupName", 'Value': asg_name}],
            ComparisonOperator="GreaterThanThreshold", Period=int(ScalingPeriod))
    except Exception as e:
        logger.error('Failed to Update High Alarm: ' + desc + ' for ASG: ' + asg_name)
        logger.error("[Alarm High Update]: {}".format(e))
        return False

    a1=alarmname + '-low'
    d1=desc+ " Low"
    try:
        cloudwatch.put_metric_alarm(AlarmName=a1, AlarmDescription=d1,
            AlarmActions=[arn_scalein],
            ActionsEnabled=True, MetricName=metricname, EvaluationPeriods=1,
            Threshold=float(ScaleDownThreshold), Statistic="Average", Namespace=namespace,
            Dimensions=[{'Name': "AutoScalingGroupName", 'Value': asg_name}],
            ComparisonOperator="LessThanThreshold", Period=int(ScalingPeriod))
    except Exception as e:
        logger.error('Failed to Update Low Alarm: ' + desc + ' for ASG: ' + asg_name)
        logger.error("[Alarm Low Update]: {}".format(e))
        return False

    return True

def UpdateDataPlaneCPUUtilization(stackname, asg_name, arn_scalein, arn_scaleout):
    """
    
    :param stackname: 
    :param asg_name: 
    :param arn_scalein: 
    :param arn_scaleout: 
    :return: 
    """
    alarmname= asg_name + '-cw-cpu'
    return common_alarm_func_update(asg_name, "DataPlaneCPUUtilization", lib.get_cw_name_space(stackname, asg_name), arn_scalein, arn_scaleout,
                        alarmname, "DataPlane CPU Utilization (New)")

def UpdateActiveSessions(stackname, asg_name, arn_scalein, arn_scaleout):
    """
    
    :param stackname: 
    :param asg_name: 
    :param arn_scalein: 
    :param arn_scaleout: 
    :return: 
    """
    logger.info('Creating Active Sessions CloudWatch alarm for ASG: ' + asg_name)

    alarmname= asg_name + '-cw-as'
    return common_alarm_func_update(asg_name, "ActiveSessions", lib.get_cw_name_space(stackname, asg_name), arn_scalein, arn_scaleout,
                        alarmname, "Active Sessions (New)")

def UpdateSessionUtilization(stackname, asg_name, arn_scalein, arn_scaleout):
    """
    
    :param stackname: 
    :param asg_name: 
    :param arn_scalein: 
    :param arn_scaleout: 
    :return: 
    """
    logger.info('Creating Session Utilization CloudWatch alarm for ASG: ' + asg_name)
    alarmname= asg_name + '-cw-su'
    return common_alarm_func_update(asg_name, "SessionUtilization", lib.get_cw_name_space(stackname, asg_name), arn_scalein, arn_scaleout,
                        alarmname, "Session Utilization (New)")
    return

def UpdateGPGatewayUtilization(stackname, asg_name, arn_scalein, arn_scaleout):
    """
    
    :param stackname: 
    :param asg_name: 
    :param arn_scalein: 
    :param arn_scaleout: 
    :return: 
    """
    logger.info('Creating GP Gateway Utilization CloudWatch alarm for ASG: ' + asg_name)
    alarmname= asg_name + '-cw-gpu'
    return common_alarm_func_update(asg_name, "GPGatewayUtilization", lib.get_cw_name_space(stackname, asg_name), arn_scalein, arn_scaleout,
                        alarmname, "GP Gateway Utilization (New)")
    return

def UpdateGPActiveTunnels(stackname, asg_name, arn_scalein, arn_scaleout):
    """
    
    :param stackname: 
    :param asg_name: 
    :param arn_scalein: 
    :param arn_scaleout: 
    :return: 
    """
    logger.info('Creating GP Active Tunnels CloudWatch alarm for ASG: ' + asg_name)
    logger.error('Not Supported Yet')
    return

def UpdateDataPlaneBufferUtilization(stackname, asg_name, arn_scalein, arn_scaleout):
    """
    
    :param stackname: 
    :param asg_name: 
    :param arn_scalein: 
    :param arn_scaleout: 
    :return: 
    """
    logger.info('Creating DP Buffer Utilization CloudWatch alarm for ASG: ' + asg_name)
    alarmname= asg_name + '-cw-dpb'
    return common_alarm_func_update(asg_name, "DataPlaneBufferUtilization", lib.get_cw_name_space(stackname, asg_name), arn_scalein, arn_scaleout,
			alarmname, "Data Plane Buffer Utilization (New)")
    return


cw_func_update_alarms = {  'DataPlaneCPUUtilization': UpdateDataPlaneCPUUtilization,
                        'ActiveSessions': UpdateActiveSessions,
                        'SessionUtilization': UpdateSessionUtilization,
                        'GPGatewayUtilization': UpdateGPGatewayUtilization,
                        'GPActiveTunnels': UpdateGPActiveTunnels,
                        'DataPlaneBufferUtilization': UpdateDataPlaneBufferUtilization}


def update_alarm(stackname, asg_name, event):
    """
    Method to update alarm parameters if they have been changed
    when the CFT stack was updated.
    
    :param stackname: 
    :param asg_name: 
    :param event: 
    :return: 
    """
    global ScaleUpThreshold
    global ScaleDownThreshold
    global ScalingParameter
    global ScalingPeriod

    r = event['ResourceProperties']
    ScaleUpThreshold = r['ScaleUpThreshold']
    ScaleDownThreshold = r['ScaleDownThreshold']
    ScalingParameter=r['ScalingParameter']
    ScalingPeriod=int(r['ScalingPeriod'])

    response=asg.describe_policies(AutoScalingGroupName=asg_name)
    arn_scalein=""
    arn_scaleout=""
    for p in response['ScalingPolicies']:
        if p['ScalingAdjustment'] < 0:
            arn_scalein=p['PolicyARN']
        elif p['ScalingAdjustment'] > 0:
            arn_scaleout=p['PolicyARN']

    if arn_scalein == "" or arn_scaleout == "":
        logger.error('Error in getting ScaleIn/ScaleOut Policy ARN')
        logger.error('Update: ARN of Scale In and Scale Out: ' + arn_scalein + ' ' + arn_scaleout)
        return False

    logger.info('Update: ARN of Scale In and Scale Out: ' + arn_scalein + ' ' + arn_scaleout)
    logger.info('Update: Adding Cloud Watch Alarm : ' + ScalingParameter + ' for ASG: ' + asg_name)
    if cw_func_update_alarms[ScalingParameter](stackname, asg_name, arn_scalein, arn_scaleout) == False:
        return False

    return True

def update_resources(event):
    """
    Method to handle any updates to the CFT templates.
    
    :param event: CFT input parameters 
    :return: None
    """
    global asg_name
    global untrust
    global PanS3KeyTpl
    global PanS3BucketTpl
    global KeyPANWPanorama
    global KeyPANWFirewall
    global ScalingParameter
    global Namespace
    global NATGateway
    global ilb_ip_address
    global ilb_name
    global elb_name
    global SubnetIDLambda
    global sgv
    global Arn

    stackname = event['ResourceProperties']['StackName']
    logger.info('Updating resources for stackname: ' + stackname)

    Arn=event['StackId']
    r = event['ResourceProperties']
    oldr = event['OldResourceProperties']
    logger.info('Dump all the new parameters')
    logger.info(r)
    logger.info('Dump all the OLD parameters')
    logger.info(oldr)

    LambdaExecutionRole = r['LambdaExecutionRole']
    stackname=r['StackName']
    PanS3BucketTpl=r['PanS3BucketTpl']
    PanS3KeyTpl=r['PanS3KeyTpl']
    KeyPANWFirewall=r['KeyPANWFirewall']
    KeyPANWPanorama=r['KeyPANWPanorama']
    ScalingParameter=r['ScalingParameter']
    NATGateway=r['NATGateway']
    elb_name=r['ELBName']
    ilb_name=r['ILBName']
    SubnetIDLambda=r['SubnetIDLambda']
    sgv= r['VPCSecurityGroup']
    ScalingParameter = r['ScalingParameter']
    MaximumInstancesASG = r['MaximumInstancesASG']
    MinInstancesASG = r['MinInstancesASG']
    ScaleUpThreshold = r['ScaleUpThreshold']
    ScaleDownThreshold = r['ScaleDownThreshold']
    ScalingPeriod = r['ScalingPeriod']
    SubnetIDUntrust = r['SubnetIDUntrust']
    MasterS3Bucket = r['MasterS3Bucket']
    LambdaENIQueue = r['LambdaENIQueue']


    SubnetIDLambda=str(lib.fix_unicode(SubnetIDLambda))
    SubnetIDLambda=lib.fix_subnets(SubnetIDLambda)

    SubnetIDUntrust=str(lib.fix_unicode(SubnetIDUntrust))
    SubnetIDUntrust=lib.fix_subnets(SubnetIDUntrust)

    logger.info('Purging queue: {}'.format(LambdaENIQueue))
    lib.purge_stack_queue(LambdaENIQueue)

    if remove_sched_func(stackname) == False:
        logger.error('Failed to delete Sched Lambda Func (VIP Monitoring)')
        return 
    create_resources(event)

    if PanS3BucketTpl == "panw-aws":
        region=r['Region']
        PanS3BucketTpl=PanS3BucketTpl + "-" + region
        PanS3KeyTpl=r['Version']
    else:
        PanS3KeyTpl=r['PanS3KeyTpl']
    logger.info('Lambda Template S3 Bucket: ' + PanS3BucketTpl + ' S3Key is : ' + PanS3KeyTpl)

    lambda_func_name= r['AddENILambda']
    try:
        lambda_client.update_function_code(FunctionName=lambda_func_name, S3Bucket=PanS3BucketTpl, S3Key=PanS3KeyTpl)
        logger.info('Updated AddENI Lambda Function Code Successfully')
    except Exception as e:
        logger.error('Update Resource for AddENI Lambda Failed')
        logger.error("[Update Resource AddENI Lambda]: {}".format(e))
        return False

    lambda_func_name= r['InitLambda']
    try:
        lambda_client.update_function_code(FunctionName=lambda_func_name, S3Bucket=PanS3BucketTpl, S3Key=PanS3KeyTpl)
        logger.info('Updated Init Lambda Function Code Successfully')
    except Exception as e:
        logger.error('Update Resource for Init Lambda Failed')
        logger.error("[Update Resource Init Lambda]: {}".format(e))
        return False

    c=read_s3_object(MasterS3Bucket, "config/init-cfg.txt")
    dict = lib.get_values_from_init_cfg(c)
    logger.info('Init CFG bootstrap file Panorama settings: ')
    logger.info(dict)
    PIP=dict['panorama-server']
    PDG=dict['dgname']
    PTPL=dict['tplname']
    Hostname=dict['hostname']

    asg_response=asg.describe_auto_scaling_groups()
    for i in asg_response['AutoScalingGroups']:
        for lbn in i['LoadBalancerNames']:
            if lbn == elb_name:
                AZ=i['AvailabilityZones']
                logger.info('Update Resource: ASG Name: ' + i['AutoScalingGroupName'])
                asg_name = i['AutoScalingGroupName']
                asg.update_auto_scaling_group(AutoScalingGroupName=asg_name, 
			MinSize=int(MinInstancesASG), MaxSize=int(MaximumInstancesASG),
			DesiredCapacity=int(MinInstancesASG), DefaultCooldown=int(ScalingPeriod))
                search = lib.get_asg_name1(stackname)
                ip=lib.substring_after(asg_name, search)
                ilb_ip_address=ip.replace("-", ".")

                logger.info('Update Resource: ASG Name: ' + i['AutoScalingGroupName'] + ' ILB-IP Address: ' + ilb_ip_address)
                update_alarm(stackname, asg_name, event)
                for ec2i in i['Instances']:
                    try:
                        instanceId=str(ec2i['InstanceId'])
                        logger.info('Updating instance: ' + instanceId + ' HealthStatus: ' + ec2i['HealthStatus'])
                        logger.info(ec2i)
                        cw=lib.get_lambda_cloud_watch_func_name(stackname, asg_name, instanceId)
                        Namespace=lib.get_cw_name_space(stackname, asg_name)
                        logger.info('Cloud Watch Lambda Function Name: ' + cw)
                        eni_response=ec2_client.describe_network_interfaces(Filters=[{'Name': "attachment.instance-id", 'Values': [instanceId]},
					{'Name': "attachment.device-index", 'Values': ["1"]}])
                        logger.info(eni_response)
                        eniId=""
                        for eni in eni_response['NetworkInterfaces']:
                            eniId=eni['NetworkInterfaceId']
                        if eniId == "":
                            logger.error('Mgmt ENI ID not found for instance: ' + instanceId)
                            continue

                        logger.info('Eni ID (eth1) for instance : ' + instanceId + ' is: ' + eniId)

                        untrust=lib.choose_subnet(SubnetIDUntrust, AZ[0])
                        #untrust="None"
                        #if NATGateway == "Yes":
                        #    lambda_response=lambda_client.get_function(FunctionName=cw)
                        #    logger.info(lambda_response)
                        #    untrust=lambda_response['Configuration']['VpcConfig']['SubnetIds']

                        if lib.delete_cw_metrics_lambda(stackname, asg_name, instanceId, None) == False:
                            logger.error('Failed to delete Lambda Function: ' + cw + ' for instance: ' + instanceId)
                            continue

                        logger.info('Delete CW Metrics function successfully: ' + cw)

                        Input = {'EC2InstanceId': instanceId, 'StackName': stackname, 'ASGName': asg_name, 'FWIP': "xxx", 'FWPIP': "xxx",
                             'KeyPANWFirewall': KeyPANWFirewall, 'KeyPANWPanorama': KeyPANWPanorama,
                             'ScalingParameter': ScalingParameter, 'Namespace': Namespace,
                             'ELBName': elb_name, 'ILBName': ilb_name,
                             'ILBIPAddress': ilb_ip_address, 'UntrustSubnet': untrust,
	                     'Arn': Arn, 'PanS3BucketTpl': PanS3BucketTpl, 'PanS3KeyTpl': PanS3KeyTpl,
                             'PIP': PIP, 'PDG': PDG, 'PTPL': PTPL, 'Hostname': Hostname}

                        for retry in range(1,5):
                            if lib.create_cw_metrics_lambda(Input, LambdaExecutionRole, eniId, NATGateway, SubnetIDLambda, sgv) == True:
                                logger.info('Re-created Lambda function for instance: ' + instanceId)
                                break

                            if retry == 4:
                                logger.error('Timeout in re-creation of Lambda function for instance: ' + instanceId)
                                break

                            time.sleep(1)
                    except Exception as e:
                        logger.error("[Error in Update Resource CW Lambda ASG Loop]: {}".format(e))
                        continue

    logger.info('Done Updating Resources...')
    return

def validate_ami_id(event):
    """
       Validate that the AMI-ID provided is a valid 
       PAN FW AMI.
       :param event: The CFT event params
       :return: bool
    """

    resource_props = event['ResourceProperties']
    ami_id = resource_props['ImageID']
    valid_ami = False
    valid_state = False

    try:
        image_info = ec2_client.describe_images(
                ImageIds=[ami_id]
        )
    except Exception, e:
        logger.info("Exception occured while retrieving AMI ID information: {}".format(e))
        return False

    logger.info('describe_images:response: {}'.format(image_info))

    ami_images = image_info['Images']
    for image in ami_images:
        product_codes = image['ProductCodes']
        for code in product_codes:
            product_code_id = code.get("ProductCodeId", None)
            if product_code_id in valid_panfw_productcode_ids.keys():
                valid_ami = True
                break

        if image['State'] == 'available':
            valid_state = True

    if valid_ami and valid_state:
        return True 

def create_resources(event):
    """
    This method is called from the lambda handler entry point.
    The following actions are performed:
        - validate the AMI-ID
        - deploys the ```sched_evt1``` lambda function.
        
    :param event: 
    :return: None 
    """
    stackname = event['ResourceProperties']['StackName']
    logger.info('Creating resources for stackname: ' + stackname)

    r = event['ResourceProperties']
    logger.info('Dump all the parameters')
    logger.info(r)

    ScalingParameter = r['ScalingParameter']
    ScalingPeriod = r['ScalingPeriod']
    StackName = r['StackName']
    VPCID = r['VPCID']
    FWInstanceType = r['FWInstanceType']
    MasterS3Bucket = r['MasterS3Bucket']
    SubnetIDTrust = r['SubnetIDTrust']
    SubnetIDUntrust = r['SubnetIDUntrust']
    SubnetIDMgmt = r['SubnetIDMgmt']
    TrustSecurityGroup = r['TrustSecurityGroup']
    UntrustSecurityGroup = r['UntrustSecurityGroup']
    MgmtSecurityGroup = r['MgmtSecurityGroup']
    VPCSecurityGroup= r['VPCSecurityGroup']
    MaximumInstancesASG = r['MaximumInstancesASG']
    ILBName = r['ILBName']
    ELBName = r['ELBName']
    SSHLocation = r['SSHLocation']
    ImageID = r['ImageID']
    ScaleUpThreshold = r['ScaleUpThreshold']
    ScaleDownThreshold = r['ScaleDownThreshold']
    KeyName = r['KeyName']
    LambdaENISNSTopic = r['LambdaENISNSTopic']
    MinInstancesASG = r['MinInstancesASG']
    Region = r['Region']
    LambdaExecutionRole = r['LambdaExecutionRole']
    FirewallBootstrapRole = r['FirewallBootstrapRole']
    ASGNotifierRole= r['ASGNotifierRole']
    ASGNotifierRolePolicy= r['ASGNotifierRolePolicy']
    KeyPANWFirewall = r['KeyPANWFirewall']
    KeyPANWPanorama = r['KeyPANWPanorama']
    NATGateway=r['NATGateway']
    SubnetIDNATGW=r['SubnetIDNATGW']
    SubnetIDLambda=r['SubnetIDLambda']
    KeyDeLicense=r['KeyDeLicense']
    LambdaENIQueue = r['LambdaENIQueue']

    print('---------------------------------------------------------------------')
    print('---Version of the Template and Lambda Code is: ' + r['Version'] + '---')
    print('---------------------------------------------------------------------')

    stackname = event['ResourceProperties']['StackName']
    logger.info('Creating Sched Lambda funcion (VIP Monitoring) for stackname: ' + stackname)
    r = event['ResourceProperties']
    lambda_exec_role_name=r['LambdaExecutionRole']
    PanS3BucketTpl=r['PanS3BucketTpl']
    if PanS3BucketTpl == "panw-aws":
        region=r['Region']
        PanS3BucketTpl=PanS3BucketTpl + "-" + region
        PanS3KeyTpl=r['Version']
    else:
        PanS3KeyTpl=r['PanS3KeyTpl']

    logger.info('Lambda Template S3 Bucket: ' + PanS3BucketTpl + ' S3Key is : ' + PanS3KeyTpl)

    event_rule_name= get_event_rule_name(stackname)
    logger.info('Creating event rule: ' + event_rule_name)
    response = events_client.put_rule(
            Name=event_rule_name,
            ScheduleExpression='rate(1 minute)',
            State='ENABLED'
        )
    events_source_arn = response.get('RuleArn')
    #time.sleep(5)
    logger.info('Getting IAM role')
    lambda_exec_role_arn = iam.get_role(RoleName=lambda_exec_role_name).get('Role').get('Arn')
    lambda_func_name= stackname + '-lambda-sched-event'
    logger.info('creating lambda function: ' + lambda_func_name)
    response = lambda_client.create_function(
            FunctionName=lambda_func_name,
            Runtime='python2.7',
            Role=lambda_exec_role_arn,
            Handler='sched_evt1.lambda_handler',
            Code={
                'S3Bucket': PanS3BucketTpl,
                'S3Key': PanS3KeyTpl
            },
            MemorySize=256,
            Timeout=120
        )
    logger.info('Lambda function created...')
    lambda_function_arn = response.get('FunctionArn')

    response = lambda_client.add_permission(
            FunctionName=lambda_function_arn,
            StatementId= stackname + '-lambda_add_perm',
            Action='lambda:InvokeFunction',
            Principal='events.amazonaws.com',
            SourceArn=events_source_arn
        )

    response = lib.describe_load_balancers(ILBName)
    ILBDNSName="None"
    if response is not None:
        for i in response['LoadBalancerDescriptions']:
            ILBDNSName = i['DNSName']

    c=read_s3_object(MasterS3Bucket, "config/init-cfg.txt")
    dict = lib.get_values_from_init_cfg(c)
    logger.info('Init CFG bootstrap file Panorama settings: ')
    logger.info(dict)
    pip=dict['panorama-server']
    pdg=dict['dgname']
    ptpl=dict['tplname']
    Input = {'ScalingParameter': ScalingParameter, 'ScalingPeriod': ScalingPeriod,
		'StackName': StackName, 'VPCID': VPCID,
		'FWInstanceType': FWInstanceType, 'MasterS3Bucket': MasterS3Bucket,
		'SubnetIDTrust': SubnetIDTrust, 'SubnetIDUntrust': SubnetIDUntrust,
		'SubnetIDMgmt': SubnetIDMgmt, 'TrustSecurityGroup': TrustSecurityGroup,
		'UntrustSecurityGroup': UntrustSecurityGroup, 'MgmtSecurityGroup': MgmtSecurityGroup,
        'VPCSecurityGroup': VPCSecurityGroup,
		'MaximumInstancesASG': MaximumInstancesASG, 'ILBName': ILBName,
		'ELBName': ELBName, 'SSHLocation': SSHLocation,
		'ImageID': ImageID, 'ScaleUpThreshold': ScaleUpThreshold,
        'ScaleDownThreshold': ScaleDownThreshold, 'KeyName': KeyName,
		'LambdaENISNSTopic': LambdaENISNSTopic,
		'MinInstancesASG': MinInstancesASG, 'Region': Region,
		'FirewallBootstrapRole': FirewallBootstrapRole,
		'LambdaExecutionRole': LambdaExecutionRole,
		'ASGNotifierRole': ASGNotifierRole,
		'ASGNotifierRolePolicy': ASGNotifierRolePolicy,
		'PanS3BucketTpl': PanS3BucketTpl,
		'PanS3KeyTpl': PanS3KeyTpl,
        'KeyPANWFirewall': KeyPANWFirewall,
        'KeyPANWPanorama': KeyPANWPanorama,
        'NATGateway': NATGateway, 'SubnetIDNATGW': SubnetIDNATGW, 'SubnetIDLambda': SubnetIDLambda,
        'ILBDNSName': ILBDNSName,
        'PIP': pip, 'PDG': pdg, 'PTPL': ptpl, 'Hostname': dict['hostname'],
        'KeyDeLicense': KeyDeLicense, 'LambdaENIQueue': LambdaENIQueue
		}

    stack_metadata= {
                'SGM': MgmtSecurityGroup, 'SGU': UntrustSecurityGroup, 'SGT': TrustSecurityGroup, 'SGV': VPCSecurityGroup,
                'IamLambda': LambdaExecutionRole, 'StackName': StackName, 'PanS3BucketTpl': PanS3BucketTpl,
                'PanS3KeyTpl': PanS3KeyTpl, 
                'ScalingParameter': ScalingParameter, 
                'SubnetIDNATGW': SubnetIDNATGW, 
                'PIP': pip, 'PDG': pdg, 'PTPL': ptpl, 'Hostname': dict['hostname']
               }
    lib.set_queue_attributes(LambdaENIQueue, 345600)
    logger.info("Send initial message onto the queue: {}".format(LambdaENIQueue))
    lib.send_message_to_queue(LambdaENIQueue, json.dumps(stack_metadata))

    logger.info('Event put targets')
    
    target_id_name = get_target_id_name(stackname)
    response= events_client.put_targets(
            Rule=event_rule_name,
            Targets=
                [{
                    'Id': target_id_name,
                    'Arn': lambda_function_arn,
                    'Input': json.dumps(Input)
                }]
        )

def delete_new_table(event):
    """
    
    :param event: 
    :return: 
    """
    stackname = event['ResourceProperties']['StackName']
    region=event['ResourceProperties']['Region']

    dynamodb = boto3.resource('dynamodb', region_name=region)
    from boto3.dynamodb.conditions import Key, Attr

    tablename=lib.get_table_name(stackname, region)

    try:
        dynamodb.delete_table(tablename)
        return True
    except Exception as e:
        logger.error("[Delete DynamoDB Table]: {}".format(e))
        return False


def create_new_table(event):
    """
    
    :param event: 
    :return: 
    """
    stackname = event['ResourceProperties']['StackName']
    region=event['ResourceProperties']['Region']

    dynamodb = boto3.resource('dynamodb', region_name=region)
    from boto3.dynamodb.conditions import Key, Attr

    tablename=lib.get_table_name(stackname, region)

    try:
        table = dynamodb.create_table(
          TableName=tablename,
          KeySchema=[
          {  
            'AttributeName': 'Type',
            'KeyType': 'HASH'  #Partition key
          },
          {  
            'AttributeName': 'Data',
            'KeyType': 'RANGE'  #Sort key (FW/ILB)
          }
         ],
         AttributeDefinitions=[
          {  
            'AttributeName': 'Data',
            'AttributeType': 'S'
          },
          {  
            'AttributeName': 'Type',
            'AttributeType': 'S'
          }
         ],
         ProvisionedThroughput={
           'ReadCapacityUnits': 10,
           'WriteCapacityUnits': 10
         }
        )
        logger.info("Table status:", table.table_status)
        return True
    except Exception as e:
        logger.error("[Create DynamoDB Table]: {}".format(e))
        return False


def get_sha(bucket, folder, lambda_sha):
    """
    Method to compute the SHA-256 encoding for the 
    contents of the given file
    :param bucket: 
    :param folder: 
    :param lambda_sha: 
    :return: 
    """
    key=folder
    key = urllib.unquote_plus(key).decode('utf8')
    try:
        response = s3.get_object(Bucket=bucket, Key=key)
        contents=response['Body'].read()
        h=hashlib.sha256()
        h.update(contents)
        hex=h.digest()
        m=base64.b64encode(hex)
        print('CodeSha256 for bucket: ' + bucket + ' file: ' + folder + ' is: ' + str(m))
        print('CodeSha256 for InitLambda: ' + lambda_sha)
        if m != lambda_sha:
            print('---------------------------------------------------------------------')
            print('   WARNING: SHA256 does not match with published code')
            print('---------------------------------------------------------------------')
        else:
            print('---------------------------------------------------------------------')
            print('Template Lambda Code SHA256 matched. Success')
            print('---------------------------------------------------------------------')
    except Exception as e:
        print(e)

def lambda_handler(event, context):
    """
        .. note:: This function is the entry point for the ```init``` Lambda function. 
           This function performs the following actions:
           
           - invokes ```create | delete | update_resources()``` based on the action 
                         required.
           - creates the ```sched_evt1``` lambda function
                        and configures the same.

           - validates that the PAN FW AMI-ID specified as input 
                        is valid and supported.

        :param event: Encodes all the input variables to the lambda function, when 
                      the function is invoked.
                      Essentially AWS Lambda uses this parameter to pass in event 
                      data to the handler function.
        :type event: dict

        :param context: AWS Lambda uses this parameter to provide runtime information to your handler.
        :type context: LambdaContext

        :return: None
    """
    global logger

    logger.info('got event{}'.format(event))

    try:
        r = event['ResourceProperties']
        lfunc=r['InitLambda']
        lresponse=lambda_client.get_function(FunctionName=lfunc)
        logger.info(json.dumps(lresponse))
        PanS3BucketTpl=r['PanS3BucketTpl']
        PanS3KeyTpl=r['PanS3KeyTpl']
        if PanS3BucketTpl != "panw-aws":
            print('---------------------------------------------------------------------')
            print('Customer is using their own template S3 bucket: ' + PanS3BucketTpl)
            print('---------------------------------------------------------------------')

        region=r['Region']
        PanS3BucketTpl="panw-aws-"+ region
        PanS3KeyTpl=r['Version']
        get_sha(PanS3BucketTpl, PanS3KeyTpl, lresponse['Configuration']['CodeSha256'])
    except Exception as e:
        logger.error("[CodeSha256]: {}".format(e))

    ami_id = event['ResourceProperties']['ImageID']
    status="SUCCESS"
    try:
        if event['RequestType'] == 'Delete':
            delete_resources(event)
            logger.info('[INFO]: Sending delete response to S3 URL for stack deletion to proceed')
        elif event['RequestType'] == 'Create':
            try:
                logger.info('Validate Ami-Id: {}'.format(ami_id))
                if not validate_ami_id(event):
                    # Check to ensure that the AMI-ID specified is valid.
                    send_response(event, context, "FAILURE: We do not support AMI-ID: {}".format(ami_id))
                    return
            except Exception as e:
                logger.error("Failed to determine validity of the AMI specified: {}".format(e))
                send_response(event, context, "FAILURE: validating AMI-ID {}. Unable to proceed".format(ami_id))
                return

            logger.info('Successfully validated that the Ami is a valid PAN FW AMI')

            try:
                stackname = event['ResourceProperties']['StackName']
                NATGateway=event['ResourceProperties']['NATGateway']
                SubnetIDNATGW=r['SubnetIDNATGW']
                SubnetIDLambda=r['SubnetIDLambda']
                if NATGateway == "Yes":
                    llen=len(SubnetIDLambda)
                    nlen=len(SubnetIDNATGW)
                    print('Length of Lambda Subnets: ' + str(llen))
                    print('Length of NATGW Subnets: ' + str(nlen))
                    if llen == 0 or nlen == 0:
                        logger.error('[ERROR]: Either Lambda or NATGW Subnets were not passed...')
                        send_response(event, context, "FAILURE: Either Lambda or NATGW Subnets were not passed")
                        return

                    if llen > 3 or nlen > 3:
                        logger.error('[ERROR]: Either Lambda or NATGW Subnets are more than 3 AZs')
                        send_response(event, context, "FAILURE: Either Lambda or NATGW Subnets are more than 3 AZs")
                        return
            except Exception as e:
                logger.error("[StackNameLenCheck]: {}".format(e))

            try:
                stackname = event['ResourceProperties']['StackName']
                NATGateway=event['ResourceProperties']['NATGateway']
                SubnetIDTrust=event['ResourceProperties']['SubnetIDTrust']
                az=len(SubnetIDTrust)
                name=""
                if NATGateway == "Yes":
                    name="-az"+str(az)+"n-"
                else:
                    name="-az"+str(az)+"-"

                print('AZ name code is: ' + name)
                sl=stackname.split(name)
                print(sl)
                print('Length of stackname is: ' + str(len(sl[0])))
                if len(sl[0]) > 10:
                    logger.error('[ERROR]: We dont support Stack Name more than 10 characters long...')
                    send_response(event, context, "FAILURE: We dont support Stack Name more than 10 characters long")
                    return
            except Exception as e:
                logger.error("[StackNameLenCheck]: {}".format(e))
                
            create_resources(event)
            logger.info('[INFO]: Sending Create response to S3 URL for stack creation to proceed')
        elif event['RequestType'] == 'Update':
            update_resources(event)
            logger.info('[INFO]: Sending Update response to S3 URL for stack.')
    except Exception as e:
        logger.error('[ERROR]: Got ERROR in Init Lamnda handler...')
        logger.error("[Error in Init Lambda Handler]: {}".format(e))

    if (send_response(event, context, status)) == 'false':
        logger.info('[ERROR]: Got ERROR in sending response to S3 URL for custom resource...')
