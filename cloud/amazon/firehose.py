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
---
module: firehose
version_added: "2.1"
short_description: create, delete, or modify an Amazon firehose instance
description:
     - Creates, deletes, or modifies firehose instances. This module has a dependency on python-boto3.
options:
  command:
    description:
      - The operation to perform on a kinesis firehose instance.
    required: true
    choices: [ 'create', 'delete', 'facts', 'modify' ]
  delivery_stream_name:
    description:
      - The name of the firehose delivery stream on which to operate.
    required: true
  configuration_type:
    description:
      - The type of firehose to create. Required when creating a firehose.
    required: false
    choices: [ 's3', 'redshift' ]
  redshift_role_arn:
    description:
      - The Role ARN required for accessing the target Redshift. Required when creating a Redshift firehose.
    required: false
  redshift_cluster_jdbcurl:
    description:
      - The JDBC URL pointing to the target Redshift instance. Required when creating a Redshift firehose.
    required: false
  redshift_copy_data_table_name:
    description:
      - The Redshift table name into which firehose will COPY. Required when creating a Redshift firehose.
    required: false
  redshift_copy_data_table_columns:
    description:
      - A comma-separated list of columns to be loaded (for CSV data).
    required: false
  redshift_copy_options:
    description:
      - A string containing options to use for the Redshift COPY command.
    required: false
  redshift_username:
    description:
      - The username required for logging in to Redshift.
    required: false
  redshift_password:
    description:
      - The password required for logging in to Redshift.
    required: false
  s3_role_arn:
    description:
      - The Role ARN used for S3 bucket access. Required when creating a firehose.
    required: false
    default: null
  s3_bucket_arn:
    description:
      - The destination S3 bucket ARN. Required when creating a firehose.
    required: false
    default: null
  s3_prefix:
    description:
      - A prefix to be added prior to 'YYYY/MM/DD' for delivered S3 files. If it ends in a slash, it appears as a folder in S3.
    required: false
    default: null
  s3_compression_format:
    description:
      - The compression format for delivering files to S3. Redshift does not support 'ZIP' or 'Snappy'.
    required: false
    choices: [ 'UNCOMPRESSED', 'GZIP', 'ZIP', 'Snappy' ]
    default: null
  s3_buffering_hints_size_in_mb:
    description:
      - The size in MB to buffer before sending to S3. Default is 5. Recommended to set to at least the size of data received every 10 seconds.
    required: false
    default: 5
  s3_buffering_interval_in_seconds:
    description:
      - The time to buffer before delivering (if the buffering size isn't exceeded). Defaults to 300 seconds.
    required: false
    default: null
  s3_encryption_no_encryption_config:
    description:
      - Specify a string here to override any encryption and ensure no encryption is used.
    required: false
    default: null
  s3_encryption_awskmskeyarn:
    description:
      - An AWS KMS Key ARN to use for encrypting data at S3. Must be in the same region as the S3 bucket.
    required: false
    default: null
  wait:
    description:
      - Should a create or modify call wait for the delivery stream to become active?
    required: false
    choices: [True, False]
    default: yes
  wait_timeout:
    description:
      - The maximum time (in sec) to wait for a delivery stream to become active.
    required: false
    default: 300
requirements:
    - "python >= 2.7"
    - "boto3"
author:
    - "Return Path (@ReturnPath)"
'''

import sys
import time

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

def validate_parameters(required_params, valid_params, module):
    command = module.params.get('command')
    for v in required_params:
        if not module.params.get(v):
            module.fail_json(msg="Parameter %s required for %s command" % (v, command))

def _has_delivery_stream_state(module, conn, state):
    delivery_stream = _describe_delivery_stream(module, conn)

    if ( 'ResponseMetadata' in delivery_stream.keys() and delivery_stream['ResponseMetadata']['HTTPStatusCode'] != 200):
        return False

    if not delivery_stream:
        if state == 'DELETED':
            return True
        else:
            return False
    if not 'DeliveryStreamStatus' in delivery_stream:
        return False
    return delivery_stream['DeliveryStreamStatus'] == state

def _describe_delivery_stream(module, conn):
    params = dict(
        DeliveryStreamName = module.params.get('delivery_stream_name')
        )
    try:
        delivery_stream = conn.describe_delivery_stream(**params)
    except botocore.exceptions.ClientError, e:
        if 'ResourceNotFoundException' in str(e):
            return None
        else:
            raise
    delivery_stream = delivery_stream['DeliveryStreamDescription']
    if 'CreateTimestamp' in delivery_stream:
        dt = str(delivery_stream['CreateTimestamp'])
        delivery_stream['CreateTimestamp'] = dt
    return delivery_stream

def await_delivery_stream_state(module, conn, state):
    wait_timeout = module.params.get('wait_timeout') + time.time()
    delivery_stream_name = module.params.get('delivery_stream_name')
    status = _has_delivery_stream_state(module, conn, state)
    while wait_timeout > time.time() and not status:
        time.sleep(5)
        if wait_timeout <= time.time():
            module.fail_json(msg="Timeout waiting for Delivery Stream %s" % delivery_stream_name)
        status = _has_delivery_stream_state(module, conn, state)
    return status

def create_delivery_stream(module, conn):
    config_type = module.params.get('configuration_type')
    wait= module.params.get('wait')

    if not config_type:
        module.fail_json(msg="You must specify a configuration type when creating a delivery stream.")
    if config_type not in ['s3', 'redshift']:
        module.fail_json(msg="configuration_type must be either 's3' or 'redshift'.")

    required_params = [
        'delivery_stream_name',
        's3_role_arn',
        's3_bucket_arn',
        ]
    valid_params = [
        's3_prefix',
        's3_compression_format',
        's3_buffering_hints_size_in_mb',
        's3_buffering_interval_in_seconds',
        's3_encryption_no_encryption_config',
        's3_encryption_awskmskeyarn',
        'wait', # These are used internally, so must be considered valid
        'wait_timeout',
        ]
    if config_type == 'redshift':
        required_params.extend([
            'redshift_role_arn',
            'redshift_cluster_jdbcurl',
            'redshift_copy_data_table_name',
            'redshift_username',
            'redshift_password',
            ])
        valid_params.extend([
            'redshift_copy_data_table_columns',
            'redshift_copy_options',
            ])
    validate_parameters(required_params, valid_params, module)

    delivery_stream = _describe_delivery_stream(module, conn)

    if delivery_stream:
        module.exit_json(changed=False)

    if module.check_mode:
        module.exit_json(changed=True)

    delivery_stream_name = module.params.get('delivery_stream_name')
    s3_role_arn = module.params.get('s3_role_arn')
    s3_bucket_arn = module.params.get('s3_bucket_arn')
    s3_prefix = module.params.get('s3_prefix')
    s3_compression_format = module.params.get('s3_compression_format')
    s3_buffering_hints_size_in_mb = module.params.get('s3_buffering_hints_size_in_mb')
    s3_buffering_interval_in_seconds = module.params.get('s3_buffering_interval_in_seconds')
    s3_encryption_no_encryption_config = module.params.get('s3_encryption_no_encryption_config')
    s3_encryption_awskmskeyarn = module.params.get('s3_encryption_awskmskeyarn')
    redshift_role_arn = module.params.get('redshift_role_arn')
    redshift_cluster_jdbcurl = module.params.get('redshift_cluster_jdbcurl')
    redshift_copy_data_table_name = module.params.get('redshift_copy_data_table_name')
    redshift_username = module.params.get('redshift_username')
    redshift_password = module.params.get('redshift_password')
    redshift_copy_data_table_columns = module.params.get('redshift_copy_data_table_columns')
    redshift_copy_options = module.params.get('redshift_copy_options')

    params = dict(
        DeliveryStreamName = module.params.get('delivery_stream_name'),
    )

    # S3 parameters are required for both S3 and Redshift, but are in different locations
    s3config = None
    if config_type == 'redshift':
        # Required Redshift parameters, and S3 config initialization
        params['RedshiftDestinationConfiguration'] = dict(
            RoleARN = redshift_role_arn,
            ClusterJDBCURL = redshift_cluster_jdbcurl,
            CopyCommand = dict(
                DataTableName = redshift_copy_data_table_name,
                ),
            Username = redshift_username,
            Password = redshift_password,
            S3Configuration = dict()
            )
        s3config = params['RedshiftDestinationConfiguration']['S3Configuration']
        rscopy = params['RedshiftDestinationConfiguration']['CopyCommand']

        # Optional Redshift parameters
        if redshift_copy_data_table_columns is not None:
            rscopy['DataTableColumns'] = redshift_copy_data_table_columns
        if redshift_copy_options is not None:
            rscopy['CopyOptions'] = redshift_copy_options

    if config_type == 's3':
        # Just initialize an S3 config section
        params['S3DestinationConfiguration'] = dict()
        s3config = params['S3DestinationConfiguration']

    # Required S3 parameters
    s3config['RoleARN'] = s3_role_arn
    s3config['BucketARN'] = s3_bucket_arn

    # Optional S3 parameters
    if s3_prefix is not None:
        s3config['Prefix'] = s3_prefix
    if s3_compression_format is not None:
        s3config['CompressionFormat'] = s3_compression_format
    if s3_buffering_hints_size_in_mb is not None or s3_buffering_interval_in_seconds is not None:
        s3config['BufferingHints'] = dict()
    if s3_buffering_hints_size_in_mb is not None:
        s3config['BufferingHints']['SizeInMBs'] = s3_buffering_hints_size_in_mb
    if s3_buffering_interval_in_seconds is not None:
        s3config['BufferingHints']['IntervalInSeconds'] = s3_buffering_interval_in_seconds
    if s3_encryption_no_encryption_config is not None or s3_encryption_awskmskeyarn is not None:
        s3config['EncryptionConfiguration'] = dict()
    if s3_encryption_no_encryption_config is not None:
        # Explicitly disabling encryption sends the hard-coded value 'NoEncryptionConfig'
        s3config['EncryptionConfiguration']['NoEncryptionConfig'] = 'NoEncryption'
    if s3_encryption_awskmskeyarn is not None:
        s3config['EncryptionConfiguration']['AWSKMSKeyARN'] = s3_encryption_awskmskeyarn

    results = conn.create_delivery_stream(**params)
    # TODO - catch exceptions, whatever those are
    if not results or ( 'ResponseMetadata' in results and results['ResponseMetadata']['HTTPStatusCode'] != 200):
        module.fail_json('Create delivery stream failed')

    if wait:
        await_delivery_stream_state(module, conn, 'ACTIVE')

    # Retrieve delivery stream data to return as facts
    delivery_stream = _describe_delivery_stream(module, conn)

    module.exit_json(changed=True, ansible_facts=dict(delivery_stream=delivery_stream))

def delete_delivery_stream(module, conn):
    required_params = ['delivery_stream_name']
    valid_params = ['wait', 'wait_timeout']
    validate_parameters(required_params, valid_params, module)

    wait= module.params.get('wait')

    delivery_stream = _describe_delivery_stream(module, conn)

    if not delivery_stream:
        module.exit_json(changed=False)

    if module.check_mode:
        module.exit_json(changed=True)

    params = dict(
        DeliveryStreamName = module.params.get('delivery_stream_name')
        )

    results = conn.delete_delivery_stream(**params)

    if wait:
        await_delivery_stream_state(module, conn, 'DELETED')

    module.exit_json(changed=True)

def facts_delivery_stream(module, conn):
    required_params = ['delivery_stream_name']
    valid_params = []
    validate_parameters(required_params, valid_params, module)

    delivery_stream = _describe_delivery_stream(module, conn)
    delivery_stream_name = module.params.get('delivery_stream_name')

    if not delivery_stream:
        module.fail_json(msg="Delivery Stream %s does not exist" % delivery_stream_name)

    module.exit_json(changed=False, ansible_facts=dict(delivery_stream=delivery_stream))

def modify_delivery_stream(module, conn):
    pass

    # TODO - no modify command yet

def main():
    # Not an ec2_argument_spec, because we're using boto3 and don't need it
    argument_spec = dict(
        command = dict(choices=['create', 'delete', 'facts', 'modify'], required=True),
        delivery_stream_name = dict(required=True),
        configuration_type = dict(choices=['s3', 'redshift'], required=False),
        redshift_role_arn = dict(required=False),
        redshift_cluster_jdbcurl = dict(required=False),
        redshift_copy_data_table_name = dict(required=False),
        redshift_copy_data_table_columns = dict(required=False),
        redshift_copy_options = dict(required=False),
        redshift_username = dict(required=False),
        redshift_password = dict(required=False),
        s3_role_arn = dict(required=False),
        s3_bucket_arn = dict(required=False),
        s3_prefix = dict(required=False),
        s3_compression_format = dict(choices=['UNCOMPRESSED', 'GZIP', 'ZIP', 'Snappy'], required=False),
        s3_buffering_hints_size_in_mb = dict(required=False),
        s3_buffering_interval_in_seconds = dict(required=False),
        s3_encryption_no_encryption_config = dict(required=False),
        s3_encryption_awskmskeyarn = dict(required=False),
        wait = dict(required=False, type='bool', default=False),
        wait_timeout = dict(required=False, type='int', default=300)
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True
    )

    if not HAS_BOTO3:
        module.fail_json(msg='boto3 required for this module')
    if not HAS_BOTO_EXCEPTIONS:
        module.fail_json(msg='botocore.exceptions required for this module')

    invocations = {
        'create': create_delivery_stream,
        'delete': delete_delivery_stream,
        'facts': facts_delivery_stream,
#        'modify': modify_delivery_stream,
    }

    firehose_conn = boto3.client('firehose')

    invocations[module.params.get('command')](module, firehose_conn)

# import module snippets
from ansible.module_utils.basic import *
from ansible.module_utils.ec2 import *

main()
