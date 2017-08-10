Palo Alto Networks Lambda Functions for ELB AutoScale Deployment
================================================================

The Lambda Functions implemented and published by Palo Alto Networks are
meant to work in conjunction with the ELB Auto Scaling Deployment on AWS.

At a high level, the goal of the lambda functions is to perform the initial
setup and the plumbing necessary to allow traffic from the internet (untrust
subnet) to the backend web tier (trust subnet) via the Palo Alto Networks
Next Generation Firewall. The policies on the PAN NGFW determine the traffic
that will be permitted to pass between the untrust and trust subnets.
Additionally, the lambda functions also handle the various actions required
when various events, such as autoscaling, occur which require the manipulation
of the firewalls.


Use Cases
+++++++++

1. Deploy Palo Alto Networks Next Generation Firewall in an auto scale
   configuration to handle unpredictable traffic patterns (spikes etc).

2. Deploy best practice architectures to secure multi-tier applications
   on AWS with Palo Alto Networks Next Generation Firewalls.


AWS Specific Deployment Options
+++++++++++++++++++++++++++++++

1. Palo Alto supports the ELB architecture to be deployed
   with optional NAT Gateways fronting back end infrastructure.
   The advantage of this configuration is to not require publicly
   routable IP addresses for various instances in the absence of the NAT
   gateway.

2. Alternatively, the ELB architecture can be deployed without NAT Gateways,
   in which case, public IP addresses will be created and assigned to the
   various nodes.


|
|
|

.. figure:: aws.png
    :align: center
    :alt: alternate text

    Fig 1. Palo Alto ELB Auto Scale Architecture


Lambda function objectives
++++++++++++++++++++++++++

    - Deploy ASG's and Bootstrap the Firewalls.
    - Deploy Lambda Functions to monitor the VIP's on the ILB.
    - Program the NAT rules on the PAN FW
    - Handle Auto Scale Events and take the necessary actions.
    - Handle the de-licensing of Firewalls when they are deleted.


Theory of Operation
+++++++++++++++++++

There are 4 main lambda functions that get deployed:

    - InitLambda
    - AddENI
    - sched_evt1
    - metrics

The two lambda functions that get deployed by the CFT are the first two listed above.

Init Lambda Function

    The InitLambda lambda function is responsible for the following functions:
    - deployment and configuration of the ```sched_evt1``` lambda function
    - handling creation, update and delete of the cloud formation template
    - validating the AMI-ID's of the PAN FW specified by the user

    When the init lambda function is triggered it validates that the AMI-ID of the PAN FW
    is valid and then proceeds to deploy the ```sched_evt1``` lambda function with all the
    required parameters. It should also be noted that the ```sched_evt1``` lambda function
    is configured to be triggered every minute. The rationale for the frequency is provided
    in the next section.

Sched_evt1 Lambda Function

    The primary objective of this lambda function is to probe (or describe / list) the IP addresses
    configured on the ILB, and for each and every IP address ensure that there is a corresponding
    ASG deployed. Conversely, if there exists an ASG without a corresponding IP address, the lambda function
    will delete the ASG.

    When a new ASG is created, callbacks to handle life-cycle hooks are also configured.
    Enabling the life-cycle hooks allows for the ```add_eni``` lambda function to take various
    actions depending upon the life cycle action. The specific actions taken will be described in the section
    which describes the ```add_eni``` lambda function description.


Add_ENI Lambda Function

    The ```add_eni``` lambda function gets invoked by a life-cycle hook trigger. The lambda function gets
    triggered when an instance in an ASG either launches or terminates. When handling an instance launch
    life-cycle hook action, the lambda function creates and attaches ENI's for the management and trust
    subnets. The lambda function is also responsible for the creation Elastic IP's if necessary and attaching
    the EIP's to the ENI's.

    Additionally, this lambda function also creates or deletes, as the case maybe, the ```metrics``` lambda
    function. The details of the ```metrics``` lambda function are described below.

Metrics Lambda Function

    The ```metrics``` lambda function is configured to be invoked every second. The objective of this function
    is to query the firewalls for various defined metrics via the XML API. The metrics retrieved from the firewall
    are subsequently consumed by the AWS Auto Scaling framework, in order to make decisions with regard to either
    keeping the number of firewalls constant, or increasing or decreasing the number of firewalls as the case maybe.

Auto Scaling Parameters
+++++++++++++++++++++++

Autoscaling on AWS occurs by defining and advertising the parameters that will be used by the AWS framework to make
auto scaling decisions. The parameters currently defined are:

    - ActiveSessions
    - DataPlaneBufferUtilization
    - DataPlaneCPUUtilization
    - GPGatewayUtilization
    - SessionUtilization

The AWS requires users to specify a ```high``` threshold and a ```low``` threshold for each parameters. When one of the
parameters breaches the high threshold mark, a scale out event is triggered. Consequently, when one of the parameters
breaches the low threshold mark, a scale in event is triggered. 

Panorama
++++++++

The use of a Panorama is optional along with the autoscaling deployment. However, it is possible to associate
a firewall with the Panorama. Panorama configuration parameters such as the IP among others can be specified
in the ```init-cfg``` file.

Logging
+++++++

The logs from the lambda functions are available as Cloud Watch Logs. Log groups are created on cloud watch,
which are prepended with the stack name.

.. note:: The logging level for the CFT stack can be modified in the following manner:

   - Create a queue on SQS, and name it with the stack name
   - Send a message with the desired logging level.

Inputs to the Lambda Functions
++++++++++++++++++++++++++++++

    Identify the various deployment artifacts such as:

    - VPC
    - Subnets (Trust, Untrust, Mgmt)
    - Security Groups
    - NAT Gateway (if any)
    - IAM Roles
    - PAN FW AMI Id
    - Lambda ENI SNS Topic
    - Lambda SQS queue
    - Bootstrap S3 bucket
    - Lambda Functions S3 bucket
    - Security Groups
    - Init Lambda Function
    - Add ENI Lambda Function
    - Key to De-license the FW
    - ELB and ILB Names
    - AWS Region
    - Auto Scale Threshold