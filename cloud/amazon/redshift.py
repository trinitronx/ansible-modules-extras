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
    zone:
        description:
            - "The DNS zone record (eg: foo.com.)"
        required: true
    state:
        description:
            - whether or not the zone should exist or not
        required: false
        default: true
        choices: [ "present", "absent" ]
    vpc_id:
        description:
            - The VPC ID the zone should be a part of (if this is going to be a private zone)
        required: false
        default: null
    vpc_region:
        description:
            - The VPC Region the zone should be a part of (if this is going to be a private zone)
        required: false
        default: null
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
            #DBName=dict(required=True),
            DBName=dict(default="gctest"),
            ClusterIdentifier=dict(required=True),
            ClusterType=dict(default='multi-node', choices=['single-node','multi-node']),
            NodeType=dict(default='dc1.large'),
            #MasterUsername=dict(required=True),
            MasterUsername=dict(default='admin'),
            #MasterUserPassword=dict(required=True),
            MasterUserPassword=dict(default='EFPefp123'),
            #VpcSecurityGroupIds=dict(required=True),
            VpcSecurityGroupIds=dict(default='sg-f516e193'),
            #ClusterSubnetGroupName=dict(required=True),
            ClusterSubnetGroupName=dict(default='efp-redshift'),
            AvailabilityZone=dict(default='us-east-1a'),
            ClusterParameterGroupName=dict(default='default.redshift-1.0'),
            AutomatedSnapshotRetentionPeriod=dict(default=1),
            Port=dict(default=5439),
            ClusterVersion=dict(default='1.0'),
            AllowVersionUpgrade=dict(default=True),
            NumberOfNodes=dict(default=4),
            PubliclyAccessible=dict(default=False),
            Encrypted=dict(default=False)))
    module = AnsibleModule(argument_spec=argument_spec)
    
    if not HAS_BOTO3:
        module.fail_json(msg='boto3 required for this module')
    
    
    DBName = module.params.get('DBName')
    ClusterIdentifier = module.params.get('ClusterIdentifier')
    ClusterType = module.params.get('ClusterType')
    NodeType = module.params.get('NodeType')
    MasterUsername = module.params.get('MasterUsername')
    MasterUserPassword = module.params.get('MasterUserPassword')
    VpcSecurityGroupIds = module.params.get('VpcSecurityGroupIds')
    ClusterSubnetGroupName = module.params.get('ClusterSubnetGroupName')
    AvailabilityZone = module.params.get('AvailabilityZone')
    ClusterParameterGroupName = module.params.get('ClusterParameterGroupName')
    AutomatedSnapshotRetentionPeriod = module.params.get('AutomatedSnapshotRetentionPeriod')
    Port = module.params.get('Port')
    ClusterVersion = module.params.get('ClusterVersion')
    AllowVersionUpgrade = module.params.get('AllowVersionUpgrade')
    NumberOfNodes = module.params.get('NumberOfNodes')
    PubliclyAccessible = module.params.get('PubliclyAccessible')
    Encrypted = module.params.get('Encrypted')

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
      Encrypted=Encrypted
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
