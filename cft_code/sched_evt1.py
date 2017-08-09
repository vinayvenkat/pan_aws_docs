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
from __future__ import print_function

import sys
import boto3
import botocore
import json
import logging
import time
import decimal
import uuid
import logging

sys.path.append('lib/')
import pan.asglib as lib

sys.path.append('dnslib/')
import pan_client as dns

# Enable creation of S3 bucket per-ASG
enable_s3=False

# Global Tunnables
dig=True
asg_tag_key="PANW-ASG"
asg_delay=30

####### GLobal Variables ############
stackname=""
region=""
ilb_name=""
elb_name=""
sg_vpc=""
sg_mgmt=""
sg_untrust=""
sg_trust=""
keyname=""
iamprofilebs=""
s3master=""
subnetmgmt=""
subnetuntrust=""
subnettrust=""
imageID=""
ScalingPeriod=300
ScaleUpThreshold=50
ScaleDownThreshold=30
ScalingParameter=""
instanceType=""
MinInstancesASG=1
MaximumInstancesASG=3
LambdaExecutionRole=""
LambdaENISNSTopic=""
ASGNotifierRole=""
ASGNotifierRolePolicy=""
PanS3BucketTpl=""
PanS3KeyTpl=""
KeyPANWFirewall=""
KeyPANWPanorama=""
NATGateway=""
SubnetIDNATGW=""
SubnetIDLambda=""
LambdaENIQueue=""
PIP=""
PDG=""
PTPL=""
Hostname=""
error_line="--------ERROR------ERROR-----ERROR------ERROR-------"

######## BOTO3 Clients and Resources #############
s3 = boto3.client('s3')
asg = boto3.client('autoscaling')
ec2 = boto3.resource('ec2')
ec2_client = ec2.meta.client
lambda_client = boto3.client('lambda')
iam = boto3.client('iam')
events_client = boto3.client('events')
cloudwatch = boto3.client('cloudwatch')
elb = boto3.client('elb')

####### FUNCTIONS ############

def fix_unicode(data):
    """
    Method to convert opaque data from unicode to utf-8
    :param data: Opaque data
    :return: utf-8 encoded data
    """
    if isinstance(data, unicode):
        return data.encode('utf-8')
    elif isinstance(data, dict):
        data = dict((fix_unicode(k), fix_unicode(data[k])) for k in data)
    elif isinstance(data, list):
        for i in xrange(0, len(data)):
            data[i] = fix_unicode(data[i])

    return data

def fix_subnets(data1):
    """
    Manipulate the subnet data and massage accordingly.
    :param data1: 
    :return: str
    """
    data=str(data1)
    data=data.replace("'", "")
    data=data.replace("[", "")
    data=data.replace("]", "")
    return data

def random_string(string_length=10):
    """
    
    :param string_length: 
    :return: 
    """
    random = str(uuid.uuid4()) 
    random = random.replace("-","") 
    return random[0:string_length]

def find_ip_address(asg_response, ip_address):
    """
    Method to check ASG's against configured IP
    addresses on the ILB. 
    
    :param asg_response: 
    :param ip_address: 
    :return: int
    """
    found=0
    asg_name = lib.get_asg_name(stackname, ip_address)
    logger.info('Finding IP address: ' + ip_address +  ' of ILB against ASG:' + asg_name)
    #logger.info(asg_response)
    for i in asg_response['AutoScalingGroups']:
        logger.info('Looking for ASG Name: ' +  asg_name + ', Item ASG Name: ' + i['AutoScalingGroupName'])
        if i['AutoScalingGroupName'] == asg_name:
            logger.info('FOUND ASG Name: ' +  asg_name)
            found=1
    return found

def common_alarm_func_add(asg_name, metricname, namespace, arn_scalein, arn_scaleout, alarmname, desc, Unit):
    """
    
    Method that supports a common interface to add cloud watch alarms along with the associated threshold 
    metrics. 
    
    :param asg_name: Name of the ASG that this alarm is associated with.
    :param metricname: Name of the metric.
    :param namespace: Name of the namespace.
    :param arn_scalein: ARN of the scale-in metric.
    :param arn_scaleout: ARN of the scale-out metric.
    :param alarmname: Name of the alarm that will be raised.
    :param desc: Description of the alarm
    :param Unit: The unit to be used.
    :return: bool
    """
    d1=desc+ " High"
    a1=alarmname + '-high'
    try:
        cloudwatch.put_metric_alarm(AlarmName=a1, AlarmDescription=d1,
            AlarmActions=[arn_scaleout],
            ActionsEnabled=True, MetricName=metricname, EvaluationPeriods=1,
            Threshold=float(ScaleUpThreshold), Statistic="Average", Namespace=namespace,
            Dimensions=[{'Name': "AutoScalingGroupName", 'Value': asg_name}],
            ComparisonOperator="GreaterThanThreshold", Period=ScalingPeriod, Unit=Unit)
    except Exception as e:
        logger.error('Failed to add High Alarm: ' + desc + ' for ASG: ' + asg_name)
        logger.error("[Alarm High Add]: {}".format(e))
        return False

    a1=alarmname + '-low'
    d1=desc+ " Low"
    try:
        cloudwatch.put_metric_alarm(AlarmName=a1, AlarmDescription=d1,
            AlarmActions=[arn_scalein],
            ActionsEnabled=True, MetricName=metricname, EvaluationPeriods=1,
            Threshold=float(ScaleDownThreshold), Statistic="Average", Namespace=namespace,
            Dimensions=[{'Name': "AutoScalingGroupName", 'Value': asg_name}],
            ComparisonOperator="LessThanThreshold", Period=ScalingPeriod,
            Unit=Unit)
    except Exception as e:
        logger.error('Failed to add Low Alarm: ' + desc + ' for ASG: ' + asg_name)
        logger.error("[Alarm Low Add]: {}".format(e))
        return False

    return True

def common_alarm_func_del(alarmname):
    """
    Common interface to delete alarms
    :param alarmname: Name of the alarm to delete.
    :return: None
    """
    a1=alarmname + '-high'
    cloudwatch.delete_alarms(AlarmNames=[a1])

    a1=alarmname + '-low'
    cloudwatch.delete_alarms(AlarmNames=[a1])
    return

## CloudWatch Alarms
def AddDataPlaneCPUUtilization(asg_name, arn_scalein, arn_scaleout):
    """
    Method to create the DataPlaneCPUUtilization Alarm. This alarm
    will trigger when the Data Plane CPU Utilization exceeds the 
    specified threshold.
    
    :param asg_name: Name of the ASG
    :param arn_scalein: ARN of the scale-in metric
    :param arn_scaleout: ARN of the scale-out metric
    :return: bool
    """
    logger.info('Creating dataPlane CPU High CloudWatch alarm for ASG: ' + asg_name)
        
    alarmname= asg_name + '-cw-cpu'
    return common_alarm_func_add(asg_name, "DataPlaneCPUUtilization", lib.get_cw_name_space(stackname, asg_name), arn_scalein, arn_scaleout,
			alarmname, "DataPlane CPU Utilization", 'Percent')

def DelDataPlaneCPUUtilization(asg_name):
    """
        Method to delete the DataPlaneCPUUtilization Alarm. This alarm
        will trigger when the Data Plane CPU Utilization exceeds the 
        specified threshold.

        :param asg_name: Name of the ASG
        :return: None
        """
    logger.info('Deleting dataPlane CPU High CloudWatch alarm for ASG: ' + asg_name)
    alarmname= asg_name + '-cw-cpu'
    common_alarm_func_del(alarmname)
    return

def AddActiveSessions(asg_name, arn_scalein, arn_scaleout):
    """
    Method to create the ActiveSessions Alarm. This alarm
    will trigger when the Active Sessions exceeds the 
    specified threshold.
    
    :param asg_name: Name of the ASG
    :param arn_scalein: ARN of the scale-in metric
    :param arn_scaleout: ARN of the scale-out metric
    :return: bool 
    """
    logger.info('Creating Active Sessions CloudWatch alarm for ASG: ' + asg_name)

    alarmname= asg_name + '-cw-as'
    return common_alarm_func_add(asg_name, "ActiveSessions", lib.get_cw_name_space(stackname, asg_name), arn_scalein, arn_scaleout,
			alarmname, "Active Sessions", 'Count')

def DelActiveSessions(asg_name):
    """
    Method to delete the Active Sessions alarm
    
    :param asg_name: Name of the ASG
    :return: None 
    """
    logger.info('Deleting Active Sessions CloudWatch alarm for ASG: ' + asg_name)

    alarmname= asg_name + '-cw-as'
    common_alarm_func_del(alarmname)
    return

def AddSessionUtilization(asg_name, arn_scalein, arn_scaleout):
    """
        Method to create the SessionUtilization Alarm. This alarm
        will trigger when the SessionUtilization exceeds the 
        specified threshold.

        :param asg_name: Name of the ASG
        :param arn_scalein: ARN of the scale-in metric
        :param arn_scaleout: ARN of the scale-out metric
        :return: bool 
    """
    logger.info('Creating Session Utilization CloudWatch alarm for ASG: ' + asg_name)
    alarmname= asg_name + '-cw-su'
    return common_alarm_func_add(asg_name, "SessionUtilization", lib.get_cw_name_space(stackname, asg_name), arn_scalein, arn_scaleout,
			alarmname, "Session Utilization", 'Percent')
    return

def DelSessionUtilization(asg_name):
    """
        Method to delete the Session Utilization alarm

        :param asg_name: Name of the ASG
        :return: None 
    """
    logger.info('Deleting Session Utilization CloudWatch alarm for ASG: ' + asg_name)
    alarmname= asg_name + '-cw-su'
    common_alarm_func_del(alarmname)
    return

def AddGPGatewayUtilization(asg_name, arn_scalein, arn_scaleout):
    """
        Method to create the GPGatewayUtilization Alarm. This alarm
        will trigger when the GPGatewayUtilization exceeds the 
        specified threshold.

        :param asg_name: Name of the ASG
        :param arn_scalein: ARN of the scale-in metric
        :param arn_scaleout: ARN of the scale-out metric
        :return: bool 
    """
    logger.info('Creating GP Gateway Utilization CloudWatch alarm for ASG: ' + asg_name)
    alarmname= asg_name + '-cw-gpu'
    return common_alarm_func_add(asg_name, "GPGatewayUtilization", lib.get_cw_name_space(stackname, asg_name), arn_scalein, arn_scaleout,
			alarmname, "GP Gateway Utilization", 'Percent')
    return

def DelGPGatewayUtilization(asg_name):
    """
    Method to delete the Session Utilization alarm

    :param asg_name: Name of the ASG
    :return: None 
    """
    logger.info('Deleting GP Gateway Utilization CloudWatch alarm for ASG: ' + asg_name)
    alarmname= asg_name + '-cw-gpu'
    common_alarm_func_del(alarmname)
    return

def AddGPActiveTunnels(asg_name, arn_scalein, arn_scaleout):
    logger.info('Creating GP Active Tunnels CloudWatch alarm for ASG: ' + asg_name)
    logger.error('Not Supported Yet')
    return

def DelGPActiveTunnels(asg_name):
    logger.info('Deleting GP Active Tunnels CloudWatch alarm for ASG: ' + asg_name)
    logger.error('Not Supported Yet')
    return

def AddDataPlaneBufferUtilization(asg_name, arn_scalein, arn_scaleout):
    """
    Method to create the DataPlaneBufferUtilization Alarm. This alarm
    will trigger when the DataPlaneBufferUtilization exceeds the 
    specified threshold.

    :param asg_name: Name of the ASG
    :param arn_scalein: ARN of the scale-in metric
    :param arn_scaleout: ARN of the scale-out metric
    :return: bool 
    """
    logger.info('Creating DP Buffer Utilization CloudWatch alarm for ASG: ' + asg_name)
    alarmname= asg_name + '-cw-dpb'
    return common_alarm_func_add(asg_name, "DataPlaneBufferUtilization", lib.get_cw_name_space(stackname, asg_name), arn_scalein, arn_scaleout,
			alarmname, "Data Plane Buffer Utilization", 'Percent')
    return

def DelDataPlaneBufferUtilization(asg_name):
    """
    Method to delete the Session Utilization alarm

    :param asg_name: Name of the ASG
    :return: None 
    """
    logger.info('Deleting DP Buffer Utilization CloudWatch alarm for ASG: ' + asg_name)
    alarmname= asg_name + '-cw-dpb'
    common_alarm_func_del(alarmname)
    return

cw_func_add_alarms = {  'DataPlaneCPUUtilization': AddDataPlaneCPUUtilization,
                        'ActiveSessions': AddActiveSessions,
                        'SessionUtilization': AddSessionUtilization,
                        'GPGatewayUtilization': AddGPGatewayUtilization,
                        'GPActiveTunnels': AddGPActiveTunnels,
                        'DataPlaneBufferUtilization': AddDataPlaneBufferUtilization}
                
cw_func_del_alarms = {  'DataPlaneCPUUtilization': DelDataPlaneCPUUtilization,
                        'ActiveSessions': DelActiveSessions,
                        'SessionUtilization': DelSessionUtilization,
                        'GPGatewayUtilization': DelGPGatewayUtilization,
                        'GPActiveTunnels': DelGPActiveTunnels,
                        'DataPlaneBufferUtilization': DelDataPlaneBufferUtilization}

def choose_subnet(subnet, AvailabilityZone):
    """
    Method to retrieve name / id of a subnet 
    in the specified Availability Zone
    
    :param subnet: 
    :param AvailabilityZone: 
    :return: 
    """
    logger.info('Choose Subnets: ')
    logger.info(subnet)
    list_subnets=subnet.split(",")
    response=ec2_client.describe_subnets(SubnetIds=list_subnets)
    ret_subnets=""
    for i in response['Subnets']:
        if i['AvailabilityZone'] == AvailabilityZone:
            if ret_subnets == "":
                ret_subnets=i['SubnetId']
            else:
                ret_subnets= ret_subnets + "," + i['SubnetId']
                
    logger.info('Return Subnets for AZ: ' + AvailabilityZone + ' Subnets: ' + ret_subnets)
    return ret_subnets
    
def create_asg_life_cycle(asg_name, AvailabilityZone, ip_address):
    """
    Method to register ASG life cycle hook actions. 
    
    
    When and ASG lifecycle hook is triggered the targets as registered
    by this method get triggered with the appropriate data fields.
    
    :param asg_name: Name of the ASG.
    :param AvailabilityZone: Name of the AZ
    :param ip_address: IP address of the instance
    :return: bool
    """
    logger.info('Creating Life Cycle Hook for ASG: ' + asg_name)
    hookname=asg_name + '-life-cycle-launch'
    mgmt=choose_subnet(subnetmgmt, AvailabilityZone)
    untrust=choose_subnet(subnetuntrust, AvailabilityZone)
    trust=choose_subnet(subnettrust, AvailabilityZone)
    if NATGateway == "Yes":
        #TODO may have to pass all subnets for better high-availability in case one NAT GW goes down
        lambda1=choose_subnet(SubnetIDLambda, AvailabilityZone)
    else:
        lambda1="None"

    metadata= {
                'MGMT': mgmt, 'UNTRUST': untrust, 'TRUST': trust,  'Namespace': lib.get_cw_name_space(stackname, asg_name),
                'KeyPANWFirewall': KeyPANWFirewall,
                'KeyPANWPanorama': KeyPANWPanorama,
                'NATGateway': NATGateway, 'SubnetIDLambda': lambda1,
                'ILBIPAddress': ip_address, 'ELBName': elb_name, 'ILBName': ilb_name,
                'KeyDeLicense': KeyDeLicense, 'LambdaENIQueue': LambdaENIQueue
    }
    
    try:
        asg.put_lifecycle_hook(LifecycleHookName=hookname, AutoScalingGroupName=asg_name,
            LifecycleTransition="autoscaling:EC2_INSTANCE_LAUNCHING",
            RoleARN=ASGNotifierRole, NotificationTargetARN=LambdaENISNSTopic,
            DefaultResult="ABANDON", HeartbeatTimeout=300,
            NotificationMetadata=json.dumps(metadata))
    except Exception as e:
        logger.error("[ASG LifeCycle Hook Launch. ROLLBACK]: {}".format(e))
        return False
    
    hookname=asg_name + '-life-cycle-terminate'
    try:
        asg.put_lifecycle_hook(LifecycleHookName=hookname, AutoScalingGroupName=asg_name,
            LifecycleTransition="autoscaling:EC2_INSTANCE_TERMINATING",
            RoleARN=ASGNotifierRole, NotificationTargetARN=LambdaENISNSTopic,
            DefaultResult="CONTINUE", HeartbeatTimeout=300,
            NotificationMetadata=json.dumps(metadata))
    except Exception as e:
        logger.error("[ASG LifeCycle Hook Terminate. ROLLBACK]: {}".format(e))
        return False
    
    return True

def create_asg(ip_address, s3_bucket_name, AvailabilityZone):
    """
    Method to create an Auto Scale Group with the configuration 
    provided. 
    
    .. note:: This method performs the following critical functions
    
       - reads in configuration from an S3 bucket
       - creates a launch configuration
       - creates an ASG
       - associates the policies with the ASG
       - registers to ASG life-cycle hook events and provides handlers for these events.
    
    :param ip_address: 
    :param s3_bucket_name: 
    :param AvailabilityZone: 
    :return: 
    """
    lc_name= lib.get_lc_name(stackname, ip_address)

    if enable_s3 == True:
       logger.info('Creating S3 bucket with name: ' + s3_bucket_name)
       response=s3.list_objects_v2(Bucket=s3master)
    
       try:
            s3.create_bucket(ACL='private', Bucket=s3_bucket_name,
		CreateBucketConfiguration={'LocationConstraint': region}) 
            for i in response['Contents']:
                copysource='{}/{}'.format(s3master, i['Key'])
                logger.info('Copy Key: ' + copysource + ' to bucket: ' + s3_bucket_name)
                s3.copy_object(Bucket=s3_bucket_name, Key=i['Key'], CopySource=copysource)

       except Exception as e:
            logger.error("[S3 bucket create error. Rollback]: {}".format(e))
            return False

    logger.info('Creating launch-config for a new ASG: ' + lc_name)
    userdata='vmseries-bootstrap-aws-s3bucket=' + s3master
    
    try:
        response=asg.create_launch_configuration(LaunchConfigurationName=lc_name, 
                ImageId=imageID, KeyName=keyname, SecurityGroups=[sg_untrust], InstanceType=instanceType,
                AssociatePublicIpAddress=False, EbsOptimized=True,
                IamInstanceProfile=iamprofilebs,
                BlockDeviceMappings=[
                        {'DeviceName': "/dev/xvda", 
                         'Ebs': 
                            {'DeleteOnTermination': True,
                             'VolumeType': 'gp2'
                            }
                        }
                ],
                UserData=userdata)
    except Exception as e:
         logger.error("[ASG LC error]: {}".format(e))
         return False

    asg_name = lib.get_asg_name(stackname, ip_address)
    logger.info('Creating Auto-Scaling Group with name: ' + asg_name)
    tags={'ResourceId': asg_name, 'ResourceType': 'auto-scaling-group', 'Key': 'Name', 'Value': asg_name, 'PropagateAtLaunch':True}
    
    subnet=choose_subnet(subnetuntrust, AvailabilityZone)
    try:
        response=asg.create_auto_scaling_group(AutoScalingGroupName=asg_name, LaunchConfigurationName=lc_name,
                MinSize=MinInstancesASG, MaxSize=MaximumInstancesASG, DesiredCapacity=MinInstancesASG,
                DefaultCooldown=ScalingPeriod, LoadBalancerNames=[elb_name],
                VPCZoneIdentifier=subnet,
                Tags=[tags],
                HealthCheckGracePeriod=900)
    except Exception as e:
         logger.error("[ASG create error]: {}".format(e))
         return False
    
    if create_asg_life_cycle(asg_name, AvailabilityZone, ip_address) == False:
        return False
    
    scalein=asg_name + '-scalein'
    try:
        response = asg.put_scaling_policy(AutoScalingGroupName=asg_name, PolicyName=scalein, AdjustmentType='ChangeInCapacity',
            ScalingAdjustment=-1, Cooldown=600)
        arn_scalein=response['PolicyARN']
    except Exception as e:
         logger.error("[ASG ScaleIn12 Policy]: {}".format(e))
         return False
         
    scaleout=asg_name + '-scaleout'
    try:
        response = asg.put_scaling_policy(AutoScalingGroupName=asg_name, PolicyName=scaleout, AdjustmentType='ChangeInCapacity',
            ScalingAdjustment=1, Cooldown=600)
        arn_scaleout=response['PolicyARN']
    except Exception as e:
         logger.info("[ASG ScaleOut123]: {}".format(e))
         return False
        
    logger.info('ARN of Scale In and Scale Out: ' + arn_scalein + ' ' + arn_scaleout)
    logger.info('Adding Cloud Watch Alarm : ' + ScalingParameter + ' for ASG: ' + asg_name)
    if cw_func_add_alarms[ScalingParameter](asg_name, arn_scalein, arn_scaleout) == False:
        return False
        
    return True

def is_another_instance_in_service(stackname, asg_name, ip):
    """
    
    :param stackname: 
    :param asg_name: 
    :param ip: 
    :return: 
    """
    asg_instances = []
    icnt = 0
    AZ=""

    ilb_response = lib.describe_load_balancers(ilb_name)
    if ilb_response == None:
        logger.error("[InServiceCheck: Cannot find Internal ELB]")
        return True

    try:
        asg_response=asg.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])
        for ec2 in asg_response['AutoScalingGroups']:
            for i in ec2['Instances']:
                AZ=ec2['AvailabilityZones']
                asg_instances.append(i['InstanceId'])
                icnt=icnt+1
        
        if icnt == 0:
            print('There are no instances in ASG: ' + asg_name)
            return True

        print('ASG instances IDs being deleted: ' + str(asg_instances))
        response = elb.describe_instance_health(LoadBalancerName=elb_name)
        #print(response)
        found=0
        for i in response['InstanceStates']:
            if i['State'] == "InService":
                iexists=False
                for iasg in asg_instances:
                    if iasg == i['InstanceId']:
                        iexists=True

                if iexists == False:
                    print('Good Instance InService: Instance: ' + i['InstanceId'])
                    found=found+1

        if found >= 1:
            print('ASG: ' + asg_name+ ' :Other instances in InService: Found ' +  str(found) + ' instances in good health')
            logger.info('Found ' +  str(found) + ' instances in good health')
            return True 
    except Exception as e:
        logger.error("[Describe ELB Instance Health]: {}".format(e))
        return False

    return False

def lookup_ilb_for_delete(ip, asg_name, response):
    """
    
    :param ip: 
    :param asg_name: 
    :param response: 
    :return: 
    """
    logger.info('Running lookup for ILB and compare with ASG')

    ilb_found=True

    ilb_response = lib.describe_load_balancers(ilb_name)
    if ilb_response == None:
        logger.error("[LookUpILB]: Cannot find Internal ELB]")
        ilb_found=False

    found=0
    if response is not None:
        for m in response:
            if ip == m:
                logger.info('IP ADDR IS SAME..NO CHANGE in the IP address. KEEP ASG. ILB: ' + ip + ' ASG: ' + asg_name)
                lib.setASGTag(asg_name, asg_tag_key, "0")
                found=1
                break

    if found == 0:
        value=lib.getASGTag(asg_name, asg_tag_key)
        cnt=0
        if value is not None:
            cnt=int(value)
            cnt=cnt+1
            logger.info('Waiting for remove ASG operation. cnt: ' + str(cnt))
            lib.setASGTag(asg_name, asg_tag_key, str(cnt))
        else:
            lib.setASGTag(asg_name, asg_tag_key, "0")


        if ilb_found == False:
                logger.info('ILBGoingAway ILBNotFound: Trigger removal of ASG associated to the ILB IP address: ' + ip + ' ASG grp name: ' + asg_name)
                lib.remove_asg(stackname, ilb_name, ip, asg_name, ScalingParameter, KeyPANWPanorama, False, False)
        elif cnt > asg_delay:
            if is_another_instance_in_service(stackname, asg_name, ip) == True:
                logger.info('ILBGoingAway: Trigger removal of ASG associated to the ILB IP address: ' + ip + ' ASG grp name: ' + asg_name)
                logger.info('Waited for : ' + str(cnt) + ' minutes before removing ASG: ' + asg_name)
                lib.remove_asg(stackname, ilb_name, ip, asg_name, ScalingParameter, KeyPANWPanorama, False, False)
            else:
                logger.error('Another instance in the ELB is not in state InService (excluding ASG instances of : ' + asg_name + ')')
                
    return

def getAz(ip, response_ilb):
    """
    Method to return the availability zone that a 
    configured IP address belongs to.
    
    :param ip: 
    :param response_ilb: 
    :return: 
    """
    for i in response_ilb['NetworkInterfaces']:
        logger.info('GetAz: Details about Internal Load Balancer')
        for k in i['PrivateIpAddresses']:
            logger.info('GetAz: IP Address of ILB is :' + k['PrivateIpAddress'])
            if k['PrivateIpAddress'] == ip:
                return i['AvailabilityZone']

    return None

def get_ilb_ip_addresses(event, content, response_ilb):
    """
    Method to retrieve the IP addresses that are configured on an 
    ILB.
    
    :param event: 
    :param content: 
    :param response_ilb: 
    :return: str 
    """
    if dig == True:
        try:
            response = lib.describe_load_balancers(ilb_name)
            if response == None:
                logger.error('Cannot find ILB: ' + ilb_name)
                return None
        except Exception as e:
             logger.error('Cannot find ILB: ' + ilb_name)
             return None

        DNSName=None
        for i in response['LoadBalancerDescriptions']:
            DNSName = i['DNSName']
        if DNSName is None:
            return None
        str=dns.pan_dig(DNSName)
        if str == "":
            logger.error('Cannot find ILB IP addresses from FQDN of ILB: ' + DNSName)
            return None

        l=str.split('\n')
        logger.info(l)
        return l

    str=""
    for i in response_ilb['NetworkInterfaces']:
        logger.info('get_ilb_ip_addresses(): Details about Internal Load Balancer')
        for k in i['PrivateIpAddresses']:
            logger.info('get_ilb_ip_addresses(): IP Address of ILB is :' + k['PrivateIpAddress'])
            str = str + " " + k['PrivateIpAddress']

    if str == "":
        return None
    
    l=str.split(" ")
    logger.info(l)
    return l

def check_ilb_health_status():
    """
       
    :return: 
    """
    # According to Narayan, we will return true for now
    return True
    try:
        response = elb.describe_instance_health(LoadBalancerName=ilb_name)
        found=0
        for i in response['InstanceStates']:
            if i['State'] == "InService":
                found=found+1

        if found >= 1:
            logger.info('Found ' +  str(found) + ' instances in good health')
            return True
    except Exception as e:
        logger.error("[Describe ELB Instance Health]: {}".format(e))
        return False

    return False


def check_and_send_message_to_queue(queue_url, str_message):
    """
    Check for the existance and the liveliness of a message on the 
    specified SQS queue.
    
    
    :param queue_url:  URL of the SQS to interrogate
    :param str_message: Message to be inserted into the queue
    :return: None
    """
    msg_str, msg_sent_timestamp, receipt_handle = lib.get_from_sqs_queue(queue_url, 20, 5)

    if not msg_str:
        logger.warning('Unable to retrieve message during this cycle.')
        return 
    msg_data = json.loads(msg_str)
    
    msg_ts = float(msg_sent_timestamp) * 0.001
    logger.info('Message from queue: {}'.format(msg_data))
    current_time = time.time()

    logger.info('msg ts: {} current ts: {}'.format(msg_ts, current_time))

    if (current_time - msg_ts) > 259200:
        logger.info('Message in queue needs to be updated')
        lib.send_message_to_queue(queue_url, str_message)
        lib.delete_message_from_queue(queue_url, receipt_handle)  
    else:
        logger.info('Message in queue is still current.')

def internal_load_balancer_work(event, context):
    """
    Method to monitor the private IP's on the Internal 
    Load Balancer and the actions as necessary.
    
    The actions performed by this function are:
        - describe (list)  the network interfaces on the ILB
        - describe (list) the currently configured auto scale groups
        - perform a comparison between the auto scale groups configured 
          and the IP's configured on the ILB.
          - if there is a mismatch, then either delete the ASG or add 
            a new ASG as the case maybe.
    
    :param event: Encodes all the input variables to the lambda function, when 
                  the function is invoked.
                  Essentially AWS Lambda uses this parameter to pass in event 
                  data to the handler function.
    :type event: dict
    
    :param context: AWS Lambda uses this parameter to provide runtime information to your handler.
    :type context: LambdaContext
    
    :return: None 
    """
    sname='ELB*' +  ilb_name + '*'
    logger.info('Running describe-network-interfaces on ILB: ' + sname)
    response_ilb = ec2_client.describe_network_interfaces(Filters=[
        {
            'Name': 'description',
            'Values': [
                sname
            ]
        } ])

    response = get_ilb_ip_addresses(event, context, response_ilb)

    print("ILB Work Time remaining (MS):", context.get_remaining_time_in_millis())
    
    logger.info('Describing auto-scaling-groups...')
    asg_response=asg.describe_auto_scaling_groups()
    #print(asg_response)
    for i in asg_response['AutoScalingGroups']:
        logger.info('ASG LoadBalancerNames: ' + str(i['LoadBalancerNames']))
        logger.info('ASG AutoScalingGroupName: ' + i['AutoScalingGroupName'])
        for lbn in i['LoadBalancerNames']:
            logger.info('ELB Name: ' + lbn)
            if lbn == elb_name:
                asg_name = i['AutoScalingGroupName']
                logger.info('FOUND ELB matching an ASG ILB: ' +  lbn + ' ASG Name: ' + asg_name)
                search = lib.get_asg_name1(stackname)
                logger.info('Search string was: ' + search)
                ip=lib.substring_after(asg_name, search)
                logger.info('Search string was: ' + search)
                ip=ip.replace("-", ".")
                logger.info('ASG name was: ' + asg_name + ' ILB Name: ' + ilb_name)
                logger.info('IP Address is: ' +  ip)
                if ip == "":
                    logger.error('Found NULL IP string for asg_name: ' + asg_name + ' and ELB name: ' + elb_name)
                    break
                logger.info('IP Address of the ILB on which DELETE operation is being invoked: ' + ip)
                lookup_ilb_for_delete(ip, asg_name, response)

    if response is not None:
        for ip in response:
            logger.info('IP Address of ILB is :' + ip)
            found = find_ip_address(asg_response, ip)
            if found == 0:
                logger.info('Insert ASG with IP address:'+ ip)
                
                ip_address = ip
                ip_address = ip_address.replace(".", "-")
                s3_bucket_name= lib.get_s3_bucket_name(stackname, ilb_name, ip_address)
                asg_name = lib.get_asg_name(stackname, ip_address)
                az=getAz(ip, response_ilb)
                if az is None:
                    logger.error('Failed to get AZ for ILB IP: ' + ip)
                    return
                logger.info('AvailabilityZone for ILB IP: ' + ip + ' Az: ' + az)
                if check_ilb_health_status() == False:
                    logger.info('ILB does not seems to have even a single private instance in good health')
                    return
                if create_asg(ip, s3_bucket_name, az) == False:
                    print(error_line)
                    lib.remove_asg(stackname, ilb_name, ip, asg_name, ScalingParameter, KeyPANWPanorama, False, False)
            else:
                logger.info('ASG with IP address already exists:' + ip)
                
    print("Time remaining return internal_load_balancer_work (MS):", context.get_remaining_time_in_millis())


def lambda_handler(event, context):
    """
    .. note:: This function is the entry point for the ```sched_event1``` Lambda function. 
    
    This function performs the following actions:
    
        | invokes ```internal_load_balancer_work()```
        |  desc: detect changes to the IP's on the ILB and take the necessary 
        |  action
          
        | invokes ```check_and_send_message_to_queue()```
        |  desc: Checks the messages on the queue to ensure its up to date
        |        and for any changes as the case maybe.
    
    :param event: Encodes all the input variables to the lambda function, when 
                  the function is invoked.
                  Essentially AWS Lambda uses this parameter to pass in event 
                  data to the handler function.
    :type event: dict
    
    :param context: AWS Lambda uses this parameter to provide runtime information to your handler.
    :type context: LambdaContext
    
    :return: None
    """


    global stackname
    global ilb_name
    global elb_name
    global region
    global sg_mgmt
    global sg_untrust
    global sg_trust
    global sg_vpc
    global keyname
    global iamprofilebs
    global s3master
    global subnetmgmt
    global subnetuntrust
    global subnettrust
    global imageID
    global ScalingPeriod
    global ScaleUpThreshold
    global ScaleDownThreshold
    global ScalingParameter
    global instanceType
    global gcontext
    global MinInstancesASG
    global MaximumInstancesASG
    global LambdaExecutionRole
    global LambdaENISNSTopic
    global ASGNotifierRolePolicy
    global ASGNotifierRole
    global PanS3BucketTpl
    global PanS3KeyTpl
    global KeyPANWFirewall
    global KeyPANWPanorama
    global NATGateway
    global SubnetIDNATGW
    global SubnetIDLambda
    global PIP
    global PDG
    global PTPL
    global Hostname
    global logger
    global KeyDeLicense
    global LambdaENIQueue

    gcontext = context
    #print("First operation remaining (MS):", context.get_remaining_time_in_millis())
    #print('Parameters {}...'.format(event))
    
    stackname=event['StackName']
    ilb_name=event['ILBName']
    elb_name=event['ELBName']
    sg_mgmt=event['MgmtSecurityGroup']
    sg_trust=event['TrustSecurityGroup']
    sg_untrust=event['UntrustSecurityGroup']
    sg_vpc=event['VPCSecurityGroup']
    keyname=event['KeyName']
    s3master=event['MasterS3Bucket']
    subnetmgmt=event['SubnetIDMgmt']
    subnettrust=event['SubnetIDTrust']
    subnetuntrust=event['SubnetIDUntrust']
    imageID=event['ImageID']
    instanceType=event['FWInstanceType']
    region=event['Region']
    iamprofilebs=str(event['FirewallBootstrapRole'])
    LambdaENISNSTopic=str(event['LambdaENISNSTopic'])
    LambdaExecutionRole=str(event['LambdaExecutionRole'])
    ASGNotifierRole=str(event['ASGNotifierRole'])
    ASGNotifierRolePolicy=str(event['ASGNotifierRolePolicy'])
    PanS3BucketTpl=event['PanS3BucketTpl']
    PanS3KeyTpl=event['PanS3KeyTpl']
    KeyPANWFirewall=event['KeyPANWFirewall']
    KeyPANWPanorama=event['KeyPANWPanorama']
    NATGateway=event['NATGateway']
    SubnetIDNATGW=event['SubnetIDNATGW']
    SubnetIDLambda=event['SubnetIDLambda']
    PIP=event['PIP']
    PDG=event['PDG']
    PTPL=event['PTPL']
    Hostname=event['Hostname']
    KeyDeLicense=event['KeyDeLicense']
    LambdaENIQueue=event['LambdaENIQueue']

    logger = logging.getLogger()
    lib.setLoggerLevel(logger, stackname, LambdaENISNSTopic)

    try:
        lfunc=lib.get_sched_func_name(stackname)
        lresponse=lambda_client.get_function(FunctionName=lfunc)
        logger.info(json.dumps(lresponse))
    except Exception as e:
        logger.info("Error getting lambda function name")
    
    subnetuntrust=str(fix_unicode(subnetuntrust))
    subnetuntrust=fix_subnets(subnetuntrust)
    
    subnetmgmt=str(fix_unicode(subnetmgmt))
    subnetmgmt=fix_subnets(subnetmgmt)
    
    subnettrust=str(fix_unicode(subnettrust))
    subnettrust=fix_subnets(subnettrust)

    SubnetIDNATGW=str(fix_unicode(SubnetIDNATGW))
    SubnetIDNATGW=fix_subnets(SubnetIDNATGW)

    SubnetIDLambda=str(fix_unicode(SubnetIDLambda))
    SubnetIDLambda=fix_subnets(SubnetIDLambda)
    
    logger.info('StackName:' +  event['StackName'])
    logger.info('ILB Name: ' + ilb_name)
    logger.info('ELB Name: ' + elb_name)
    logger.info('Mgmt Security Group ID : ' + sg_mgmt)
    logger.info('KeyName is :' + keyname)
    logger.info('S3 Master Bucket :' + s3master)
    logger.info('iamprofilebs: ' + iamprofilebs)
    logger.info('Subnet Mgmt List: ' + subnetmgmt)
    logger.info('Subnet Untrust List: ' + subnetuntrust)
    logger.info('Subnet Trust List: ' + subnettrust)
    if PIP != "":
        logger.info('Panorama IP is: ' + PIP)

    ScalingPeriod = int(event['ScalingPeriod'])
    ScaleUpThreshold = float(event['ScaleUpThreshold'])
    ScaleDownThreshold = float(event['ScaleDownThreshold'])
    ScalingParameter = event['ScalingParameter']
    MinInstancesASG = int(event['MinInstancesASG'])
    MaximumInstancesASG = int(event['MaximumInstancesASG']) 

    stack_metadata= {
                'SGM': sg_mgmt, 'SGU': sg_untrust, 'SGT': sg_trust, 'SGV': sg_vpc,
                'IamLambda': LambdaExecutionRole, 'StackName': stackname, 'PanS3BucketTpl': PanS3BucketTpl,
                'PanS3KeyTpl': PanS3KeyTpl, 
                'ScalingParameter': ScalingParameter, 
                'SubnetIDNATGW': SubnetIDNATGW, 
                'PIP': PIP, 'PDG': PDG, 'PTPL': PTPL, 'Hostname': Hostname
               }

    check_and_send_message_to_queue(LambdaENIQueue, json.dumps(stack_metadata))

    logger.info('First Time remaining (MS):' + str(context.get_remaining_time_in_millis()))
    internal_load_balancer_work(event, context)
    
    logger.info('DONE: Last Operations: Time remaining (MS):' + str(context.get_remaining_time_in_millis()))
