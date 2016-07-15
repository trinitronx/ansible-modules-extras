#!/usr/bin/python
# pylint disable=c0111
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
version_added: "2.2"
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
        aliases: ['cluster_identifier', 'cluster_id']
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
    cluster_security_groups:
        description:
            - "A list of cluster security groups to be associated with the cluster."
        required: false
        default: null
    cluster_subnet_group_name:
        description:
            - The name of a cluster subnet group to be associated with this cluster.
            - "If this parameter is not provided the resulting cluster will be deployed outside virtual private cloud (VPC)."
        required: false
        default: null
        aliases: [ 'cluster_subnet_group_name' ]
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
    hsm_client_cert_id:
        description:
          - "The name of the HSM client certificate the cluster uses to retrieve the data encryption keys stored in an HSM."
        required: false
        default: null
        aliases: [ 'hsm_client_certificate_identifier', 'hsm_client_cert_identifier' ]
    hsm_configuration_id:
        description:
          - "The name of the HSM configuration that contains the information the cluster can use to retrieve and store keys in an HSM."
        required: false
        default: null
        aliases: [ 'hsm_configuration_identifier', 'hsm_config_identifier' ]
    elastic_ip:
        description:
          - "The Elastic IP (EIP) address for the cluster."
          - "Constraints: The cluster must be provisioned in EC2-VPC and publicly-accessible through an Internet gateway."
          - "For more information about provisioning clusters in EC2-VPC, go to Supported Platforms to Launch Your Cluster in the Amazon Redshift Cluster Management Guide."
        required: false
        default: null
    tags:
        description:
            - tags dict to apply to a resource. Used with command=create, command=facts.
        required: false
        default: null
    kms_key_id:
        description:
            - "The AWS Key Management Service (KMS) key ID of the encryption key that you want to use to encrypt data in the cluster."
        required: false
        default: null
    iam_roles:
        description:
            - "A list of AWS Identity and Access Management (IAM) roles that can be used by the cluster to access other AWS services."
            - "You must supply the IAM roles in their Amazon Resource Name (ARN) format."
            - "You can supply up to 10 IAM roles in a single request."
        required: false
        default: null
    wait:
        description:
          - When command=create, replicate, modify or restore then wait for the database to enter the 'available' state.  When command=delete wait for the database to be terminated.
        required: false
        default: "no"
        choices: [ "yes", "no" ]
    comment:
        description:
            - Comment associated with the zone
        required: false
        default: ''
    skip_final_cluster_snapshot:
        description:
            - "During deletion: if false, save a final snapshot of the cluster to final_cluster_snapshot_id before deleting."
            - final_cluster_snapshot_id is required unless skip_final_cluster_snapshot is true
        required: true
        default: false
    final_cluster_snapshot_id:
        description:
            - A string identifier for a cluster snapshot taken when the cluster is deleted. Required on deletion if skip_final_cluster_snapshot is false
            - final_cluster_snapshot_id is required unless skip_final_cluster_snapshot is true
        required: false
        default: null
extends_documentation_fragment:
    - aws
    - ec2
author: "Return Path (@ReturnPath, @gc1code, @LesBarstow, @trinitronx)"
'''

EXAMPLES = '''
- name: Get Private Subnets for VPC
  local_action:
    module: ec2_vpc_subnet_facts
    filters:
      "tag:private": true
  register: vpc_private_subnets
  tags:
    - vpc_private_subnets
    - redshift_cluster_subnet_group
    - redshift

- name: Prepare Redshift Cluster Subnet Group
  local_action:
    module: redshift_cluster_subnet_group
    command: create
    name: "{{ redshift_subnet_group.name }}"
    description: "{{ redshift_subnet_group.description }}"
    subnets: "{{ vpc_private_subnets.subnets | map(attribute='id') | list }}"
    tags: "{{ redshift_subnet_group.tags }}"
  register: redshift_subnet_group_result
  tags:
    - redshift_cluster_subnet_group
    - redshift

- name: Create RedShift Cluster
  local_action:
    module: redshift
    command: create
    name: "{{ redshift_cluster_name }}"
    node_type: "{{ redshift_node_type | default('dc1.large') }}"
    username: "{{ redshift_username }}"
    password: "{{ redshift_password }}"
    db_name: "{{ redshift_db_name }}"
    cluster_type: multi-node
    num_nodes: 4
    backup_retention: 35
    db_port: 5439
    allow_version_upgrade: false
    public: true
    wait: true
    vpc_security_groups: "sg-12cd34ef0"
    parameter_group: "default.redshift-1.0"
    subnet: "{{ redshift_subnet_group.name }}"
    zone: "{{ vpc_private_subnets.subnets | map(attribute='availability_zone') | list | first }}"
    maint_window: "mon:03:00-mon:03:30"
  register: redshift_create_result
  tags:
    - redshift

- name: Get facts for RedShift Cluster
  local_action:
    module: redshift
    name: "{{ redshift_cluster_name }}"
    command: facts
  register: redshift_test
  tags:
    - redshift

- name: Delete RedShift Cluster
  local_action:
    module: redshift
    name: "{{ redshift_cluster_name }}"
    skip_final_cluster_snapshot: true
    command: delete
  register: redshift_delete_result
  tags:
    - redshift

# Print out the registered results
- name: Debug stuff
  debug: var={{ item }}
  with_items:
    - redshift_create_result
    - redshift_test
    - redshift_delete_result
  tags: redshift

- name: Generate RedShift JDBC url
  debug: msg="jdbc:redshift://{{ redshift_test['ansible_facts']['ec2_redshift']['Endpoint']['Address'] }}:{{ redshift_test['ansible_facts']['ec2_redshift']['Endpoint']['Port'] }}/{{ redshift_test['ansible_facts']['ec2_redshift']['DBName'] }}"
  tags:
    - redshift

- name: Add DNS CNAME for RedShift Cluster Endpoint
  local_action:
    module: route53
    command: create
    overwrite: yes
    zone: "{{ redshift_dns_zone }}"
    record: "{{ redshift_cluster_name }}.{{ redshift_dns_zone }}."
    type: CNAME
    ttl: 300
    value: "{{ redshift_test['ansible_facts']['ec2_redshift']['Endpoint']['Address'] }}"
  tags:
    - redshift
    - route53

'''

RETURN = '''
changed:
  description: A flag indicating if any change was made or not
  returned: success
  type: boolean
  sample: true
failed:
  description: A flag indicating if any command resulted in an error
  returned: failure
  type: boolean
  sample: true
invocation:
  description: Invocation information for the Ansible module (args passed)
  returned: success
  type: dict
  sample: |
    {
        "module_args": {
          "allow_version_upgrade": null,
          "backup_retention": 1,
          "cluster_security_groups": null,
          "cluster_type": null,
          "cluster_version": null,
          "command": "facts",
          "db_name": "dev",
          "db_port": 123,
          "elastic_ip": null,
          "encrypted": null,
          "final_cluster_snapshot_id": null,
          "hsm_client_cert_id": null,
          "hsm_configuration_id": null,
          "iam_roles": null,
          "kms_key_id": null,
          "maint_window": null,
          "name": "message-data",
          "node_type": null,
          "num_nodes": null,
          "parameter_group": null,
          "password": null,
          "public": null,
          "skip_final_cluster_snapshot": null,
          "subnet": null,
          "tags": null,
          "username": null,
          "vpc_security_groups": null,
          "wait": false,
          "zone": null
        },
        "module_name": "redshift"
      }

ansible_facts:
  description: The redshift cluster information returned as ansible_facts
  returned: success
  type: complex dict
  sample: |
    # Sample for 'create', and 'facts' commands on same cluster will look the same
    {
        "ansible_facts": {
            "ec2_redshift": {
              "AllowVersionUpgrade": false,
              "AutomatedSnapshotRetentionPeriod": 35,
              "AvailabilityZone": "us-east-1b",
              "ClusterCreateTime": "2016-07-14 18:41:17.645000+00:00",
              "ClusterIdentifier": "test-data",
              "ClusterNodes": [
                {
                  "NodeRole": "LEADER",
                  "PrivateIPAddress": "10.123.45.1",
                  "PublicIPAddress": "52.12.34.56"
                },
                {
                  "NodeRole": "COMPUTE-0",
                  "PrivateIPAddress": "10.123.45.2",
                  "PublicIPAddress": "52.12.34.78"
                },
                {
                  "NodeRole": "COMPUTE-1",
                  "PrivateIPAddress": "10.123.45.3",
                  "PublicIPAddress": "52.12.34.90"
                },
                {
                  "NodeRole": "COMPUTE-2",
                  "PrivateIPAddress": "10.123.45.4",
                  "PublicIPAddress": "52.12.34.12"
                },
                {
                  "NodeRole": "COMPUTE-3",
                  "PrivateIPAddress": "10.123.45.5",
                  "PublicIPAddress": "52.12.34.34"
                }
              ],
              "ClusterParameterGroups": [
                {
                  "ParameterApplyStatus": "in-sync",
                  "ParameterGroupName": "default.redshift-1.0"
                }
              ],
              "ClusterPublicKey": "ssh-rsa AAAABBCCCCDDDDEEEEFFFFGGGGGHHHHHHHIIIIIIIJJJJJJ+K+LLLL+MMMM/NNNN/OOO+/PPPP Amazon-Redshift\\n",
              "ClusterRevisionNumber": "1069",
              "ClusterSecurityGroups": [],
              "ClusterStatus": "available",
              "ClusterSubnetGroupName": "test-redshift",
              "ClusterVersion": "1.0",
              "DBName": "testdata",
              "Encrypted": false,
              "Endpoint": {
                "Address": "test-data.cdefghijklnm.us-east-1.redshift.amazonaws.com",
                "Port": 5439
              },
              "MasterUsername": "redshiftuser",
              "NodeType": "ds2.xlarge",
              "NumberOfNodes": 4,
              "PendingModifiedValues": {},
              "PreferredMaintenanceWindow": "sun:10:00-sun:10:30",
              "PubliclyAccessible": true,
              "Tags": [],
              "VpcId": "vpc-12ab34cd",
              "VpcSecurityGroups": [
                {
                  "Status": "active",
                  "VpcSecurityGroupId": "sg-12cd34ef0"
                }
              ]
            }
          }
    }
    # Sample for 'delete' command has ClusterStatus deleting
    {
      "ansible_facts": {
        "ec2_redshift": {
          "Cluster": {
            "PubliclyAccessible": true,
            "MasterUsername": "redshiftuser",
            "VpcSecurityGroups": [
              {
                "Status": "active",
                "VpcSecurityGroupId": "sg-12cd34ef0"
              }
            ],
            "NumberOfNodes": 4,
            "PendingModifiedValues": {},
            "VpcId": "vpc-12ab34cd",
            "ClusterVersion": "1.0",
            "Tags": [],
            "AutomatedSnapshotRetentionPeriod": 35,
            "ClusterParameterGroups": [
              {
                "ParameterGroupName": "default.redshift-1.0",
                "ParameterApplyStatus": "in-sync"
              }
            ],
            "DBName": "testdata",
            "PreferredMaintenanceWindow": "mon:05:00-mon:05:30",
            "Endpoint": {
              "Port": 5439,
              "Address": "test-data.cdefghijklnm.us-east-1.redshift.amazonaws.com"
            },
            "AllowVersionUpgrade": false,
            "ClusterCreateTime": "2016-07-14 22:48:10.692000+00:00",
            "ClusterSubnetGroupName": "test-redshift",
            "ClusterSecurityGroups": [],
            "ClusterIdentifier": "test-data",
            "AvailabilityZone": "us-east-1b",
            "NodeType": "ds2.xlarge",
            "Encrypted": false,
            "ClusterStatus": "deleting"
          },
          "ResponseMetadata": {
            "HTTPStatusCode": 200,
            "RequestId": "12345678-abcd-1122-2233-ffeeddccbbaa"
          }
        }
      }
    }

'''

# TODO: http://docs.ansible.com/ansible/developing_modules.html
# https://boto3.readthedocs.org/en/latest/reference/services/redshift.html

# pylint: disable=c0413
import time
import json
import datetime

try:
    import boto3
    HAS_BOTO3 = True
except ImportError:
    HAS_BOTO3 = False
try:
    import botocore.exceptions
    HAS_BOTO_EXCEPTIONS = True
except ImportError:
    HAS_BOTO_EXCEPTIONS = False

def _recursive_dict_datetime_to_str(node):
    """ Walk an iterable dict or list, and string-ify any datetimes found """
    # print ""
    # print "Recursive Dict Walk Called"
    new_node = node
    # Enumerate over anything enumerable (dict, list)
    # pylint: disable=c0103
    for k, v in enumerate(node):
        # First, try to index it like a list
        try:
            # print "%s -> %s" % (k, v)
            # (index by 0,1,2...)
            if isinstance(v, datetime.datetime):
                # print "FOUND DATETIME"
                new_node[k] = str(new_node[k])
            else:
                new_node[k] = _recursive_dict_datetime_to_str(node[k])
                # print "Set new_node[%s] -> %s" % (k, new_node[k])
        except KeyError:
            # Numeric key did not exist... it's something else
            # print "NOT A LIST"
            if isinstance(node[v], list):
                new_node[v] = _recursive_dict_datetime_to_str(node[v])
                # print "Set new_node[%s] -> %s" % (v, new_node[v])
            elif isinstance(node[v], dict):
                # It's a dict (index by 'k1','k2','k3'...)
                new_node[v] = _recursive_dict_datetime_to_str(node[v])
                # print "Set new_node[%s] -> %s" % (v, new_node[v])
            else:
                # We are on a leaf node or dict key
                # print "LEAF NODE OR DICT KEY"
                try:
                    if isinstance(node[v], datetime.datetime):
                        new_node[v] = str(node[v])
                        # print "Set new_node[%s] -> %s" % (v, new_node[v])
                except KeyError:
                    # not a a dict key...
                    pass
                if isinstance(v, datetime.datetime):
                    # print "FOUND DATETIME"
                    new_node[k] = str(v)
    return new_node

def validate_parameters(required_params, valid_params, module):
    """
    Check required & valid parameters for given command
    """
    command = module.params.get('command')
    for param in dict.keys(module.params):
        ignored_params = set(dict.keys(module.params)) - set(valid_params)
        if required_params:
            ignored_params = ignored_params - set(required_params)
        all_params = set(valid_params) | set(required_params) if required_params else valid_params
        if module.params.get(param) and param not in ignored_params and param not in all_params:
            module.fail_json(msg="Parameter %s is not valid for %s command" % (param, command))
    if required_params:
        for val in required_params:
            if not module.params.get(val):
                module.fail_json(msg="Parameter %s required for %s command" % (val, command))

def _describe_cluster(module, conn):
    cluster_identifier = module.params.get('name')
    if not cluster_identifier:
        return None
    params = dict(
        ClusterIdentifier=cluster_identifier
        )
    cluster_facts = None
    try:
        cluster_facts = conn.describe_clusters(**params)
    except botocore.exceptions.ClientError as err:
        if 'ClusterNotFound' in err:
            return None

    if not cluster_facts:
        return None
    if 'Clusters' not in cluster_facts:
        return None
    if not cluster_facts['Clusters']:
        return None

    cluster_facts = cluster_facts['Clusters'][0]

    # Convert datetime.datetime object to string - exit_json isn't doing so...
    if isinstance(cluster_facts, dict) or isinstance(cluster_facts, list):
        cluster_facts = _recursive_dict_datetime_to_str(cluster_facts)

    return cluster_facts
# pylint: disable=r0914,r0915,r0912,i0011
def create_cluster(module, conn):
    """ Create RedShift Cluster """
    required_params = [
        'name',
        'node_type',
        'username',
        'password',
        ]
    valid_params = [
        'name',
        'node_type',
        'username',
        'password',
        'db_name',
        'cluster_type',
        'cluster_security_groups',
        'vpc_security_groups',
        'subnet',
        'zone',
        'maint_window',
        'parameter_group',
        'backup_retention',
        'db_port',
        'cluster_version',
        'allow_version_upgrade',
        'num_nodes',
        'public',
        'encrypted',
        'hsm_client_cert',
        'hsm_configuration_id',
        'elastic_ip',
        'kms_key_id',
        'tags',
        'wait',
        'wait_timeout',
        ]
    validate_parameters(required_params, valid_params, module)

    cluster_facts = _describe_cluster(module, conn)

    if cluster_facts:
        module.exit_json(
            changed=False,
            ansible_facts=json.loads(json.dumps(dict(
                ec2_redshift=cluster_facts
            )))
        )

    if module.check_mode:
        module.exit_json(changed=True)

    cluster_identifier = module.params.get('name')
    node_type = module.params.get('node_type')
    master_username = module.params.get('username')
    master_user_password = module.params.get('password')
    db_name = module.params.get('db_name')
    cluster_type = module.params.get('cluster_type')
    cluster_security_groups = module.params.get('cluster_security_groups'),
    if cluster_security_groups is not None and all(x is None for x in cluster_security_groups):
        cluster_security_groups = None
    vpc_security_group_ids = module.params.get('vpc_security_groups')
    if vpc_security_group_ids is not None and all(x is None for x in vpc_security_group_ids):
        vpc_security_group_ids = None
    cluster_subnet_group_name = module.params.get('subnet')
    availability_zone = module.params.get('zone')
    cluster_parameter_group_name = module.params.get('parameter_group')
    backup_retention = module.params.get('backup_retention')
    port = module.params.get('db_port')
    cluster_version = module.params.get('cluster_version')
    allow_version_upgrade = module.params.get('allow_version_upgrade')
    number_of_nodes = module.params.get('num_nodes')
    publicly_accessible = module.params.get('public')
    encrypted = module.params.get('encrypted')
    hsm_client_cert_id = module.params.get('hsm_client_cert_id')
    hsm_configuration_id = module.params.get('hsm_configuration_id')
    elastic_ip = module.params.get('elastic_ip')
    tags = module.params.get('tags')
    kms_key_id = module.params.get('kms_key_id')
    iam_roles = module.params.get('iam_roles')

    params = dict(
        ClusterIdentifier=cluster_identifier,
        NodeType=node_type,
        MasterUsername=master_username,
        MasterUserPassword=master_user_password,
        )
    opt_params = dict(
        DBName=db_name,
        ClusterType=cluster_type,
        ClusterSecurityGroups=cluster_security_groups,
        VpcSecurityGroupIds=vpc_security_group_ids,
        ClusterSubnetGroupName=cluster_subnet_group_name,
        AvailabilityZone=availability_zone,
        ClusterParameterGroupName=cluster_parameter_group_name,
        AutomatedSnapshotRetentionPeriod=backup_retention,
        Port=port,
        ClusterVersion=cluster_version,
        AllowVersionUpgrade=allow_version_upgrade,
        NumberOfNodes=number_of_nodes,
        PubliclyAccessible=publicly_accessible,
        Encrypted=encrypted,
        HsmClientCertificateIdentifier=hsm_client_cert_id,
        HsmConfigurationIdentifier=hsm_configuration_id,
        ElasticIp=elastic_ip,
        KmsKeyId=kms_key_id,
        IamRoles=iam_roles,
        Tags=tags
        )

    # Don't send parameters without values
    for k, val in opt_params.items():
        if val is None:
            del opt_params[k]

    params.update(opt_params)

    response = conn.create_cluster(**params)

    if response['ResponseMetadata']['HTTPStatusCode'] != 200:
        module.fail_json(msg='create_cluster failed')

    # Do the wait thing
    if module.params.get('wait'):
        waiter = conn.get_waiter('cluster_available')

        try:
            waiter.wait(ClusterIdentifier=cluster_identifier)
        except botocore.exceptions.WaiterError as err:
            module.fail_json(msg='cluster cannot be found %s' % (err))

    response = conn.describe_clusters(
        ClusterIdentifier=cluster_identifier
    )

    # Convert nested datetime.datetime object to string
    if isinstance(response, dict) or isinstance(response, list):
        response = _recursive_dict_datetime_to_str(response)

    if not response or response['ResponseMetadata']['HTTPStatusCode'] != 200:
        module.fail_json(msg="cluster failed to start: %s" % (response['ResponseMetadata']))

    module.exit_json(
        changed=True,
        ansible_facts=json.loads(json.dumps(dict(
            cluster=response
        )))
    )

def facts_cluster(module, conn):
    """ Get RedShift Cluster Facts """
    required_params = [
        'name'
        ]
    valid_params = [
        'wait',
        'wait_timeout'
        ]

    validate_parameters(required_params, valid_params, module)

    cluster_id = module.params.get('name')
    cluster_facts = _describe_cluster(module, conn)

    if not cluster_facts:
        module.fail_json(msg='Unable to find cluster %s' % (cluster_id))

    module.exit_json(
        changed=False,
        ansible_facts=dict(
            ec2_redshift=json.loads(json.dumps(cluster_facts))
            )
        )

def delete_cluster(module, conn):
    """ Delete RedShift Cluster """
    required_params = ['name']
    # Note: final_cluster_snapshot_id is required unless skip_final_cluster_snapshot is specified
    if not module.params.get('skip_final_cluster_snapshot'):
        required_params.append('final_cluster_snapshot_id')
    else:
        required_params.append('skip_final_cluster_snapshot')

    valid_params = [
        'skip_final_cluster_snapshot',
        'final_cluster_snapshot_id',
        'wait',
        'wait_timeout'
        ]
    validate_parameters(required_params, valid_params, module)

    cluster_identifier = module.params.get('name')
    skip_final_cluster_snapshot = module.params.get('skip_final_cluster_snapshot')
    final_cluster_snapshot_id = module.params.get('final_cluster_snapshot_id')

    cluster_facts = _describe_cluster(module, conn)

    if not cluster_facts:
        module.exit_json(changed=False)

    if module.check_mode:
        module.exit_json(changed=True)

    params = dict(
        ClusterIdentifier=cluster_identifier,
        )

    if skip_final_cluster_snapshot is not None:
        params['SkipFinalClusterSnapshot'] = skip_final_cluster_snapshot
    if final_cluster_snapshot_id is not None:
        params['final_cluster_snapshot_id'] = final_cluster_snapshot_id

    try:
        response = conn.delete_cluster(**params)
    except botocore.exceptions.ClientError as err:
        module.fail_json(msg="error deleting cluster: %s" % (err))


    # Convert datetime.datetime object to string - exit_json and running through
    # json.loads(json.dumps(...)) does not work here :-/
    # pylint: disable=w0612
    if isinstance(response, dict) or isinstance(response, list):
        response = _recursive_dict_datetime_to_str(response)
        # for key1, val1 in enumerate(response['Clusters']):
        #     for key2, val2 in response['Clusters'][key1].iteritems():
        #         if isinstance(val2, datetime.datetime):
        #             response['Clusters'][key1][key2] = str(val2)

    # Do the wait thing
    if module.params.get('wait'):
        waiter = conn.get_waiter('cluster_deleted')

        try:
            waiter.wait(ClusterIdentifier=cluster_identifier)
        except botocore.exceptions.WaiterError as err:
            module.fail_json(msg='error waiting for cluster to be deleted: %s' % (err))

    module.exit_json(
        changed=True,
        ansible_facts=dict(
            ec2_redshift=json.loads(json.dumps(response))
            )
        )


def main():
    """ module main function """
    # pylint: disable=c0326,c0301
    argument_spec = dict(
        command               = dict(required=True, choices=['create', 'replicate', 'delete', 'facts', 'modify', 'promote', 'snapshot', 'reboot', 'restore']),
        name                  = dict(required=True, aliases=['cluster_identifier', 'cluster_id']),
        node_type             = dict(required=False, choices=['ds1.xlarge', 'ds1.8xlarge', 'ds2.xlarge', 'ds2.8xlarge', 'dc1.large', 'dc1.8xlarge']),
        username              = dict(required=False, aliases=['master_username']),
        password              = dict(required=False, aliases=['master_password']),
        db_name               = dict(required=False, default='dev'),
        cluster_type          = dict(required=False, choices=['single-node','multi-node']),
        cluster_security_groups = dict(required=False,  aliases=['cluster_security_group_ids']),
        vpc_security_groups   = dict(required=False, type='list', aliases=['vpc_security_group_ids']),
        subnet                = dict(required=False, aliases=['cluster_subnet_group_name']),
        zone                  = dict(required=False, aliases=['aws_zone', 'ec2_zone', 'availability_zone']),
        maint_window          = dict(required=False, aliases=['maintenance_window', 'preferred_maintenance_window']),
        parameter_group       = dict(required=False, aliases=['cluster_parameter_group_name']),
        backup_retention      = dict(required=False, type='int', default=1, aliases=['automated_snapshot_retention', 'automated_snapshot_retention_period']),
        db_port               = dict(required=False, type='int', default=5439, aliases=['port']),
        cluster_version       = dict(required=False, aliases=['engine_version']),
        allow_version_upgrade = dict(required=False, type='bool'),
        num_nodes             = dict(required=False, type='int', aliases=['number_of_nodes']),
        public                = dict(required=False, type='bool', aliases=['publicly_accessible']),
        encrypted             = dict(required=False, type='bool'),
        hsm_client_cert_id    = dict(required=False, aliases=['hsm_client_certificate_identifier', 'hsm_client_cert_identifier']),
        hsm_configuration_id  = dict(required=False, aliases=['hsm_configuration_identifier', 'hsm_config_identifier']),
        elastic_ip            = dict(required=False),
        tags                  = dict(required=False, type='dict'),
        kms_key_id            = dict(required=False),
        wait                  = dict(required=False, type='bool', default=False),
        skip_final_cluster_snapshot = dict(required=False, type='bool'),
        final_cluster_snapshot_id = dict(required=False, aliases=['final_cluster_snapshot_identifier']),
        iam_roles             = dict(required=False, type='list')
    )
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)

    if not HAS_BOTO3:
        module.fail_json(msg='boto3 required for this module')
    if not HAS_BOTO_EXCEPTIONS:
        module.fail_json(msg='botocore.exceptions required for this module')

    invocations = {
        'create': create_cluster,
        'delete': delete_cluster,
        'facts': facts_cluster,
        # 'modify': modify_cluster
    }

    redshift_conn = boto3.client('redshift')

    invocations[module.params.get('command')](module, redshift_conn)
# pylint disable=E0401
from ansible.module_utils.basic import *
from ansible.module_utils.ec2 import *

main()
