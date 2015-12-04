#!/usr/bin/python
# This file is part of Ansible
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.

DOCUMENTATION = '''
module: redshift
short_description: add or delete redshift cluster
description:
    - Creates and deletes redshift clusters
version_added: "2.0"
options:
    command:
        description:
          - Specifies the action to take. The 'reboot' option is available starting at version 2.0
        required: true
        choices: [ 'create', 'replicate', 'delete', 'facts', 'modify' , 'promote', 'snapshot', 'reboot', 'restore' ]
    name:
        description:
            - "The name of the redshift cluster to create (eg: my-redshift-cluster)"
        required: true
        aliases=['cluster_identifier', 'cluster_id']
    db_name:
        description:
            - The name of the first database to be created when the cluster is created.
            - "To create additional databases after the cluster is created, connect to the cluster with a SQL client and use SQL commands to create a database. For more information, go to [Create a Database](http://docs.aws.amazon.com/redshift/latest/dg/t_creating_database.html) in the Amazon Redshift Database Developer Guide."
        required: false
        default: dev
    username:
        description:
            - Master database username. Used only when command=create.
        required: false
        default: admin
    password:
        description:
            - Password for the master database username. Used only when command=create or command=modify.
        required: true
        default: null
    zone:
        description:
            - "The EC2 Availability Zone (AZ) in which you want Amazon Redshift to provision the cluster. For example, if you have several EC2 instances running in a specific Availability Zone, then you might want the cluster to be provisioned in the same zone in order to decrease network latency."
            - "Default: A random, system-chosen Availability Zone in the region that is specified by the endpoint."
            - "Example: us-east-1d"
            - "Constraint: The specified Availability Zone must be in the same region as the current endpoint."
        required: false
        default: null
    vpc_id:
        description:
            - The identifier of the VPC the cluster is in, if the cluster is in a VPC.
        required: false
        default: null
    vpc_security_groups:
        description:
            - "A list of Virtual Private Cloud (VPC) security groups to be associated with the cluster."
            - "Default: The default VPC security group is associated with the cluster."
        required: false
        default: null
    cluster_subnet_group_name:
        description:
            - The name of a cluster subnet group to be associated with this cluster.
            - "If this parameter is not provided the resulting cluster will be deployed outside virtual private cloud (VPC)."
        required: false
        default: null
        aliases: [ 'cluster_subnet_group_name' ]
    zone:
        description:
            - "The EC2 Availability Zone (AZ) in which you want Amazon Redshift to provision the cluster. For example, if you have several EC2 instances running in a specific Availability Zone, then you might want the cluster to be provisioned in the same zone in order to decrease network latency."
            - "Default: A random, system-chosen Availability Zone in the region that is specified by the endpoint."
            - "Example: us-east-1d"
            - "Constraint: The specified Availability Zone must be in the same region as the current endpoint."
        aliases: [ 'aws_zone', 'ec2_zone', 'availability_zone' ]
    parameter_group:
        description:
          - Name of the DB parameter group to associate with this instance.  If omitted then the default Amazon Redshift cluster parameter group will be used. For information about the default parameter group, go to [Working with Amazon Redshift Parameter Groups](http://docs.aws.amazon.com/redshift/latest/mgmt/working-with-parameter-groups.html). Used only when command=create or command=modify.
        required: false
        default: null
        aliases: [ 'cluster_parameter_group_name' ]
    backup_retention:
        description:
          - "Number of days automated snapshots are retained.  Set to 0 to disable backups.  Default is 1 day.  Valid range: 0-35. Even if automated snapshots are disabled, you can still create manual snapshots when you want with CreateClusterSnapshot. Used only when command=create or command=modify."
        required: false
        default: 1
        aliases: [ 'automated_snapshot_retention', 'automated_snapshot_retention_period' ]
    maint_window:
        description:
          - "The weekly time range (in UTC) during which automated cluster maintenance can occur."
          - "Format: ddd:hh24:mi-ddd:hh24:mi"
          - "Default: A 30-minute window selected at random from an 8-hour block of time per region, occurring on a random day of the week. For more information about the time blocks for each region, see Maintenance Windows in Amazon Redshift Cluster Management Guide."
          - "Valid Days: Mon | Tue | Wed | Thu | Fri | Sat | Sun"
          - "Constraints: Minimum 30-minute window."
        required: false
        default: null
        aliases: [ 'maintenance_window', 'preferred_maintenance_window' ]
    cluster_version:
        description:
          - "The version of the Amazon Redshift engine software that you want to deploy on the cluster."
          - "The version selected runs on all the nodes in the cluster."
          - "Constraints: Only version 1.0 is currently available."
        required: false
        default: '1.0'
        aliases: [ 'engine_version' ]
    allow_version_upgrade:
        description:
          - "If true, major version upgrades can be applied during the maintenance window to the Amazon Redshift engine that is running on the cluster."
          - "When a new major version of the Amazon Redshift engine is released, you can request that the service automatically apply upgrades during the maintenance window to the Amazon Redshift engine that is running on your cluster."
        required: false
        default: true
    db_port:
        description:
          - "The port number on which the cluster accepts incoming connections."
          - "The cluster is accessible only via the JDBC and ODBC connection strings. Part of the connection string requires the port on which the cluster will listen for incoming connections."
          - "Valid Values: 1150-65535"
        required: false
        default: 5439
    num_nodes:
        description:
          - "The number of compute nodes in the cluster. This parameter is required when the ClusterType parameter is specified as multi-node."
          - "For information about determining how many nodes you need, go to Working with Clusters in the Amazon Redshift Cluster Management Guide."
          - "If you don't specify this parameter, you get a single-node cluster. When requesting a multi-node cluster, you must specify the number of nodes that you want in the cluster."
          - "Constraints: Value must be at least 1 and no more than 100."
        required: false
        default: 1
        aliases: [ 'number_of_nodes' ]
    public:
        description:
          - "If true, the cluster can be accessed from a public network."
        required: false
        default: false
        aliases: [ 'publicly_accessible' ]
    encrypted:
        description:
          - "If true, the data in the cluster is encrypted at rest."
        required: false
        default: false
    wait:
        description:
          - When command=create, replicate, modify or restore then wait for the database to enter the 'available' state.  When command=delete wait for the database to be terminated.
        required: false
        default: "no"
        choices: [ "yes", "no" ]
    wait_timeout:
        description:
          - how long before wait gives up, in seconds
        default: 900
    comment:
        description:
            - Comment associated with the zone
        required: false
        default: ''
extends_documentation_fragment:
    - aws
    - ec2
author: "Greg Colburn (@gc1code)"
'''

# TODO: http://docs.ansible.com/ansible/developing_modules.html
# https://boto3.readthedocs.org/en/latest/reference/services/redshift.html

import time

try:
    import boto3
    HAS_BOTO3 = True
except ImportError:
    HAS_BOTO3 = False


def main():
    argument_spec = ec2_argument_spec()
    argument_spec.update(dict(
            command               = dict(choices=['create', 'replicate', 'delete', 'facts', 'modify', 'promote', 'snapshot', 'reboot', 'restore'], required=True),
            name                  = dict(required=True, aliases=['cluster_identifier', 'cluster_id']),
            db_name               = dict(default='dev', required=False),
            cluster_type          = dict(default='multi-node', choices=['single-node','multi-node']),
            node_type             = dict(default='dc1.large', choices=['ds1.xlarge', 'ds1.8xlarge', 'ds2.xlarge', 'ds2.8xlarge', 'dc1.large', 'dc1.8xlarge']),
            username              = dict(default='admin'),
            password              = dict(required=True),
            vpc_security_groups   = dict(required=False, aliases=['vpc_security_group_ids']),
            subnet                = dict(required=False, aliases=['cluster_subnet_group_name']),
            zone                  = dict(aliases=['aws_zone', 'ec2_zone', 'availability_zone']),
            maint_window          = dict(required=False, aliases=['maintenance_window', 'preferred_maintenance_window']),
            parameter_group       = dict(required=False, aliases=['cluster_parameter_group_name']),
            backup_retention      = dict(required=False, type='int', default=1, aliases=['automated_snapshot_retention', 'automated_snapshot_retention_period']),
            db_port               = dict(required=False, type='int', default=5439, aliases=['port']),
            cluster_version       = dict(required=False, default='1.0', aliases=['engine_version']),
            allow_version_upgrade = dict(required=False, type='bool', default=False),
            num_nodes             = dict(required=False, type='int', default=1, aliases=['number_of_nodes']),
            wait                  = dict(type='bool', default=False),
            wait_timeout          = dict(type='int', default=900),
            public                = dict(type='bool', default=False, aliases=['publicly_accessible']),
            encrypted             = dict(type='bool', default=False),
            tags                  = dict(type='dict', required=False)
## TODO:
## HsmClientCertificateIdentifier='string',
## HsmConfigurationIdentifier='string',
## ElasticIp='string',
        )
    )
    module = AnsibleModule(argument_spec=argument_spec)
    
    if not HAS_BOTO3:
        module.fail_json(msg='boto3 required for this module')
    
    
    DBName = module.params.get('db_name')
    ClusterIdentifier = module.params.get('name')
    ClusterType = module.params.get('cluster_type')
    NodeType = module.params.get('node_type')
    MasterUsername = module.params.get('username')
    MasterUserPassword = module.params.get('password')
    VpcSecurityGroupIds = module.params.get('vpc_security_groups')
    ClusterSubnetGroupName = module.params.get('subnet')
    AvailabilityZone = module.params.get('zone')
    ClusterParameterGroupName = module.params.get('parameter_group')
    AutomatedSnapshotRetentionPeriod = module.params.get('backup_retention')
    Port = module.params.get('db_port')
    ClusterVersion = module.params.get('cluster_version')
    AllowVersionUpgrade = module.params.get('allow_version_upgrade')
    NumberOfNodes = module.params.get('num_nodes')
    PubliclyAccessible = module.params.get('public')
    Encrypted = module.params.get('encrypted')
    Tags = module.params.get('tags')
# region, ec2_url, aws_connect_params = get_aws_connection_info(module)
# xyz = connect_to_aws(boto.xyz, region, **aws_connect_params)
    
    client = boto3.client('redshift')
    
    #TODO: make idempotent
    # check for existance of cluster with name DBName
    
    response = client.create_cluster(
      DBName=DBName,
      ClusterIdentifier=ClusterIdentifier,
      ClusterType=ClusterType,
      NodeType=NodeType,
      MasterUsername=MasterUsername,
      MasterUserPassword=MasterUserPassword,
      VpcSecurityGroupIds=[
          VpcSecurityGroupIds
      ],
      ClusterSubnetGroupName=ClusterSubnetGroupName,
      AvailabilityZone=AvailabilityZone,
      ClusterParameterGroupName=ClusterParameterGroupName,
      AutomatedSnapshotRetentionPeriod=AutomatedSnapshotRetentionPeriod,
      Port=Port,
      ClusterVersion=ClusterVersion,
      AllowVersionUpgrade=AllowVersionUpgrade,
      NumberOfNodes=NumberOfNodes,
      PubliclyAccessible=PubliclyAccessible,
      Encrypted=Encrypted,
      Tags=Tags
      )
      
    
    if (response['ResponseMetadata']['HTTPStatusCode'] != 200):
        module.fail_json(msg='create_cluster failed')
    
      
    # Do the wait thing
    waiter = client.get_waiter('cluster_available')
    
    try:
        waiter.wait(ClusterIdentifier=ClusterIdentifier)
    except botocore.exceptions.WaiterError, e:
        module.fail_json(msg='cluster cannot be found')
      
    response = client.describe_clusters(
        ClusterIdentifier=ClusterIdentifier
    )
    
    if (response['ResponseMetadata']['HTTPStatusCode'] != 200):
        module.fail_json(msg='cluster failed to start')
    
    module.exit_json(
        changed=True,
        ansible_facts=dict(
            endpoint=response['Clusters'][0]['Endpoint']['Address']
        )
    )

from ansible.module_utils.basic import *
from ansible.module_utils.ec2 import *

main()
