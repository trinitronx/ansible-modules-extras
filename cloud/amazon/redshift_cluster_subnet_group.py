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

DOCUMENTATION = '''
module: redshift_cluster_subnet_group
short_description: add or delete redshift cluster subnet group
description:
    - Creates and deletes redshift cluster subnet groups
version_added: "2.0"
options:
    command:
        description:
          - Specifies the action to take.
        required: true
        choices: [ 'create', 'delete', 'facts' ]
    name:
        description:
            - "The name of the redshift cluster subnet group to create (eg: my-redshift-cluster-subnet-group)"
            - "Constraints:"
            - "  Must contain no more than 255 alphanumeric characters or hyphens."
            - "  Must not be 'Default'."
            - "  Must be unique for all subnet groups that are created by your AWS account."
        required: true
        aliases: ['cluster_subnet_group_name']
    description:
        description:
            - "A description for the subnet group."
        required: false
        default: null
    subnets:
        description:
            - "An array of VPC subnet IDs. A maximum of 20 subnets can be modified in a single request."
        required: false
        default: null
        aliases: ['subnet_ids']
    tags:
        description:
            - tags dict to apply to a resource. Used with command=create, command=facts.
        required: false
        default: null
    max_records:
        description:
            - Max records returned by describe_cluster_subnet_groups(). Used with command=create, command=facts.
        required: false
        default: 100
extends_documentation_fragment:
    - aws
    - ec2
author: "Return Path (@ReturnPath)"
'''

RETURN = '''
changed:
    description: A flag indicating if any change was made or not
    returned: success
    type: boolean
    sample: true
failed:
    description: A flag indicating if any command resulted in an error ('facts' returns failed: true when no matching subnet groups are found)
    returned: failure
    type: boolean
    sample: true
invocation:
    description: Invocation information for the Ansible module (args passed)
    returned: success
    type: dict
    sample:
        {
          "invocation": {
            "module_args": {
              "subnets": [
                "subnet-ab123456",
                "subnet-cd456789",
                "subnet-98765432",
                "subnet-12345678"
              ],
              "command": "create",
              "description": "Test RedShift Subnet Group",
              "name": "test-redshift-subnet-group",
              "tags": {
                "environment": "prod",
                "product": "foo",
                "Name": "Test RedShift Subnet Group",
                "location": "us-east-1"
              }
            }
          }
        }
ansible_facts:
    description: The subnet group information returned as ansible_facts
    returned: success
    type: complex dict
    sample:
    # Sample for 'create' command:
        {
          "ansible_facts": {
            "cluster_subnet_groups": {
              "ClusterSubnetGroups": [
                {
                  "Subnets": [
                    {
                      "SubnetStatus": "Active",
                      "SubnetIdentifier": "subnet-ab123456",
                      "SubnetAvailabilityZone": {
                        "Name": "us-east-1b"
                      }
                    },
                    {
                      "SubnetStatus": "Active",
                      "SubnetIdentifier": "subnet-cd456789",
                      "SubnetAvailabilityZone": {
                        "Name": "us-east-1e"
                      }
                    },
                    {
                      "SubnetStatus": "Active",
                      "SubnetIdentifier": "subnet-98765432",
                      "SubnetAvailabilityZone": {
                        "Name": "us-east-1c"
                      }
                    },
                    {
                      "SubnetStatus": "Active",
                      "SubnetIdentifier": "subnet-12345678",
                      "SubnetAvailabilityZone": {
                        "Name": "us-east-1d"
                      }
                    }
                  ],
                  "VpcId": "vpc-badcafe0",
                  "Description": "Test RedShift Subnet Group",
                  "Tags": [
                    {
                      "Value": "foo",
                      "Key": "product"
                    },
                    {
                      "Value": "Test RedShift Subnet Group",
                      "Key": "Name"
                    },
                    {
                      "Value": "us-east-1",
                      "Key": "location"
                    },
                    {
                      "Value": "prod",
                      "Key": "environment"
                    }
                  ],
                  "SubnetGroupStatus": "Complete",
                  "ClusterSubnetGroupName": "test-redshift-subnet-group"
                }
              ],
              "ResponseMetadata": {
                "HTTPStatusCode": 200,
                "RequestId": "1234abcd-cdef-ff00-00ff-f00dcafebeef"
              }
            }
          }
        }

    # Sample for 'delete' command
    {
      "ec2_redshift_cluster_subnet_group": {
        "ResponseMetadata": {
          "HTTPStatusCode": 200,
          "RequestId": "1234abcd-cdef-ff00-00ff-f00dcafebeef"
        }
      }
    }
'''
# http://docs.ansible.com/ansible/developing_modules.html
# https://boto3.readthedocs.org/en/latest/reference/services/redshift.html


# def validate_parameters(required_params, valid_params, module):
#     """ Validates module parameters """
#     command = module.params.get('command')
#     if required_params:
#         for val in required_params:
#             if not module.params.get(val):
#                 module.fail_json(msg="Parameter %s required for %s command" % (val, command))

def validate_parameters(required_params, valid_params, module):
    """
    Check required & valid parameters for given command
    """
    command = module.params.get('command')
    for param in dict.keys(module.params):
        print "module.params.get(%s): %s" % (param, module.params.get(param))
        if module.params.get(param) and param != 'command' and param not in valid_params:
            module.fail_json(msg="Parameter %s is not valid for %s command" % (param, command))
    if required_params:
        for val in required_params:
            if not module.params.get(val):
                module.fail_json(msg="Parameter %s required for %s command" % (val, command))

def _describe_cluster_subnet_group(module, conn):
    """
    Returns a list of Amazon Redshift parameter groups,
    including parameter groups you created and the default parameter group.
    For each parameter group, the response includes the parameter group name,
    description, and parameter group family name.
    You can optionally specify a name to retrieve the description of a specific parameter group.

    For more information about parameters and parameter groups,
    go to Amazon Redshift Parameter Groups in the Amazon Redshift Cluster Management Guide.


    If you specify both tag keys and tag values in the same request,
    Amazon Redshift returns all parameter groups that match any combination of the
    specified keys and values.
    For example, if you have owner and environment for tag keys,
    and admin and test for tag values, all parameter groups that have
    any combination of those values are returned.

    If both tag keys and values are omitted from the request,
    parameter groups are returned regardless of whether they
    have tag keys or values associated with them.
    """
    cluster_subnet_group_name = module.params.get('name')
    if not cluster_subnet_group_name:
        return None
    max_records = module.params.get('max_records')
    marker = module.params.get('marker')
    tags = module.params.get('tags')

    params = dict(
        ClusterSubnetGroupName=cluster_subnet_group_name
        )

    opt_params = dict(
        MaxRecords=max_records,
        Marker=marker,
        TagKeys=_tags_to_keys(tags),
        TagValues=_tags_to_values(tags)
        )

    # Don't send parameters without values
    for key, val in opt_params.items():
        if val is None:
            print "Deleting %s -> %s" % (key, val)
            del opt_params[key]

    params.update(opt_params)
    print "Updated params %s" % (params)

    cluster_subnet_group_facts = None
    try:
        cluster_subnet_group_facts = conn.describe_cluster_subnet_groups(**params)
    except botocore.exceptions.ClientError, error:
        if 'ClusterNotFound' in error:
            return None

    if not cluster_subnet_group_facts:
        return None
    if 'ClusterSubnetGroups' not in cluster_subnet_group_facts:
        return None
    if not cluster_subnet_group_facts['ClusterSubnetGroups']:
        return None

    return cluster_subnet_group_facts

def _tags_to_dictlist(tags):
    if not tags:
        return None
    dictlist = []
    for key, value in tags.iteritems():
        temp = {'Key': key, 'Value': value}
        dictlist.append(temp)
    return dictlist

def _tags_to_keys(tags):
    if not tags:
        return None
    return dict.keys(tags)

def _tags_to_values(tags):
    if not tags:
        return None
    return dict.values(tags)

def get_resource_tags(vpc_conn, resource_id):
    """ Gets all tags """
    return dict((t.name, t.value) for t in
                vpc_conn.get_all_tags(filters={'resource-id': resource_id}))


def ensure_tags(vpc_conn, resource_id, tags, add_only, check_mode):
    """ Ensure tags are updated / deleted if needed """
    try:
        cur_tags = get_resource_tags(vpc_conn, resource_id)
        if cur_tags == tags:
            return {'changed': False, 'tags': cur_tags}

        to_delete = dict((k, cur_tags[k]) for k in cur_tags if k not in tags)
        if to_delete and not add_only:
            vpc_conn.delete_tags(resource_id, dict.keys(to_delete), dry_run=check_mode)

        to_add = dict((k, tags[k]) for k in tags if k not in cur_tags or cur_tags[k] != tags[k])
        if to_add:
            vpc_conn.create_tags(resource_id, _tags_to_dictlist(to_add), dry_run=check_mode)

        latest_tags = get_resource_tags(vpc_conn, resource_id)
        return {'changed': True, 'tags': latest_tags}
    except EC2ResponseError as e:
        raise AnsibleTagCreationException(
            'Unable to update tags for {0}, error: {1}'.format(resource_id, e))

# pylint: disable=r0914
def create_cluster_subnet_group(module, conn):
    """
    Creates a new Amazon Redshift subnet group.
    You must provide a list of one or more subnets in your existing Amazon Virtual Private Cloud
    (Amazon VPC) when creating Amazon Redshift subnet group.

    For information about subnet groups,
    go to Amazon Redshift Cluster Subnet Groups in the Amazon Redshift Cluster Management Guide.
    http://docs.aws.amazon.com/redshift/latest/mgmt/working-with-cluster-subnet-groups.html
    """
    required_params = [
        'name',
        'description',
        'subnets'
        ]
    valid_params = [
        'name',
        'description',
        'subnets',
        'tags'
        ]
    validate_parameters(required_params, valid_params, module)

    cluster_subnet_group_facts = _describe_cluster_subnet_group(module, conn)

    if cluster_subnet_group_facts:
        module.exit_json(
            changed=False,
            ansible_facts=json.loads(json.dumps(dict(
                cluster_subnet_groups=cluster_subnet_group_facts
            )))
        )

    if module.check_mode:
        module.exit_json(changed=True)

    cluster_subnet_group_name = module.params.get('name')
    description = module.params.get('description')
    subnet_ids = module.params.get('subnets')
    tags = _tags_to_dictlist(module.params.get('tags'))

    params = dict(
        ClusterSubnetGroupName=cluster_subnet_group_name,
        Description=description,
        SubnetIds=subnet_ids
        )
    opt_params = dict(
        Tags=tags
        )

    # Don't send parameters without values
    for key, val in opt_params.items():
        if val is None:
            del opt_params[key]

    params.update(opt_params)

    response = conn.create_cluster_subnet_group(**params)

    if response['ResponseMetadata']['HTTPStatusCode'] != 200:
        module.fail_json(msg='create_cluster_subnet_group failed')

    # Do the wait thing
    # if module.params.get('wait'):
    #     waiter = conn.get_waiter('cluster_available')

    #     try:
    #         waiter.wait(ClusterIdentifier=ClusterIdentifier)
    #     except botocore.exceptions.WaiterError, e:
    #         module.fail_json(msg='cluster cannot be found')

    # response = conn.describe_clusters(
    #     ClusterIdentifier=ClusterIdentifier
    # )

    # Convert datetime.datetime object to string - exit_json and running through
    # json.loads(json.dumps(...)) does not work here :-/
    # for k,v in enumerate(response['Clusters']):
    #   for k2,v2 in response['Clusters'][k].iteritems():
    #     if isinstance(v2, datetime.datetime):
    #       response['Clusters'][k][k2] = str( v2 )
    for key, val in response['ClusterSubnetGroup'].iteritems():
        if isinstance(val, datetime.datetime):
            response['ClusterSubnetGroup'][key] = str(val)
        if isinstance(val, list):
            for key2, val2 in enumerate(response['ClusterSubnetGroup'][key]):
                if isinstance(val2, datetime.datetime):
                    response['ClusterSubnetGroup'][key][key2] = str(val2)

    if not response or response['ResponseMetadata']['HTTPStatusCode'] != 200:
        module.fail_json(
            msg='cluster subnet group could not be created. Response was: {:s}'.format(response)
        )

    module.exit_json(
        changed=True,
        ansible_facts=json.loads(json.dumps(dict(
            ec2_redshift_cluster_subnet_group=response
        )))
    )

def facts_cluster_subnet_group(module, conn):
    """
    Returns one or more cluster subnet group objects, 
    which contain metadata about your cluster subnet groups.
    By default, this operation returns information about all cluster subnet groups
    that are defined in you AWS account.

    If you specify both tag keys and tag values in the same request,
    Amazon Redshift returns all subnet groups that match any combination of the
    specified keys and values.
    For example, if you have owner and environment for tag keys, and admin and test for tag values,
    all subnet groups that have any combination of those values are returned.

    If both tag keys and values are omitted from the request,
    subnet groups are returned regardless of whether they have
    tag keys or values associated with them.
    """
    required_params = None
    valid_params = [
        'name',
        'max_records',
        'marker',
        'tags'
        ]
    validate_parameters(required_params, valid_params, module)

    cluster_subnet_group_name = module.params.get('name')
    cluster_subnet_group_facts = _describe_cluster_subnet_group(module, conn)

    if not cluster_subnet_group_facts:
        module.fail_json(msg='Unable to find cluster subnet group %s' % (cluster_subnet_group_name))

    module.exit_json(
        changed=False,
        ansible_facts=dict(
            ec2_redshift_cluster_subnet_group=json.loads(json.dumps(cluster_subnet_group_facts))
            )
        )

def delete_cluster_subnet_group(module, conn):
    """ Deletes the specified cluster subnet group. """
    required_params = ['name']
    valid_params = ['name']
    validate_parameters(required_params, valid_params, module)

    cluster_subnet_group_name = module.params.get('name')

    cluster_subnet_group_facts = _describe_cluster_subnet_group(module, conn)

    if not cluster_subnet_group_facts:
        module.exit_json(changed=False)

    if module.check_mode:
        module.exit_json(changed=True)

    params = dict(
        ClusterSubnetGroupName=cluster_subnet_group_name,
        )

    response = conn.delete_cluster_subnet_group(**params)

    module.exit_json(
        changed=True,
        ansible_facts=json.loads(json.dumps(dict(
            ec2_redshift_cluster_subnet_group=response
        )))
        )

def main():
    """ module main function """
    argument_spec = dict(
        command=dict(required=True, choices=['create', 'delete', 'facts']),
        name=dict(required=True, aliases=['cluster_subnet_group_name']),
        description=dict(required=False),
        subnets=dict(required=False, type='list', aliases=['subnet_ids']),
        tags=dict(type='dict', required=False),
    )
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)

    if not HAS_BOTO3:
        module.fail_json(msg='boto3 required for this module')
    if not HAS_BOTO_EXCEPTIONS:
        module.fail_json(msg='botocore.exceptions required for this module')

    invocations = {
        'create': create_cluster_subnet_group,
        'delete': delete_cluster_subnet_group,
        'facts': facts_cluster_subnet_group
    }

    redshift_conn = boto3.client('redshift')

    invocations[module.params.get('command')](module, redshift_conn)

# pylint: disable=c0413
from ansible.module_utils.basic import *
from ansible.module_utils.ec2 import *

main()
