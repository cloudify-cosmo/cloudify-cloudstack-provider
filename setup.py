########
# Copyright (c) 2013 GigaSpaces Technologies Ltd. All rights reserved
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
#    * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    * See the License for the specific language governing permissions and
#    * limitations under the License.

__author__ = 'adaml'

from setuptools import setup

VERSION = '1.0'

COSMO_CLI_VERSION = '3.0'
COSMO_CLI_BRANCH = 'develop'
COSMO_CLI = 'https://github.com/cloudify-cosmo/cloudify-cli/tarball/' \
            '{0}#egg=cloudify-cli-{1}'.format(
    COSMO_CLI_BRANCH, COSMO_CLI_VERSION)

setup(
    name='cloudify-cloudstack-provider',
    version=VERSION,
    author='adaml',
    author_email='adaml@gigaspaces.com',
    packages=['cloudify_exoscale','cloudify_cloudstack'],
    license='LICENSE',
    description='the cloudify cloudstack provider',
    package_data={'cloudify_exoscale': ['cloudify-config.yaml',
                                        'cloudify-config.defaults.yaml'],
                  'cloudify_cloudstack':['cloudify-config.yaml',
                                        'cloudify-config.defaults.yaml']},
    install_requires=[
        "scp",
        "fabric",
        "jsonschema",
        "IPy",
        "PyYAML",
        "apache-libcloud>=0.14.1",
        "cloudify-cli"
    ],
    dependency_links=[COSMO_CLI]
)
