#!/usr/bin/env python
# -*- coding: utf-8 -*-

import base64
import boto3
import botocore
import configparser
import getpass
import json
import os
import requests
import signal
import time
from bs4 import BeautifulSoup
from cli.log import LoggingApp
from xml.etree import ElementTree

try:
    input = raw_input
    import urlparse
except NameError:
    import urllib.parse as urlparse
    pass

DESCRIPTION = """This is a script to provide CLI access using single-sign-on
federated access to AWS accounts. It allows you to login with SSO credentials,
and will provide SAML profiles which is used by the AWS CLI tool or SDKs
to authenticate you with AWS, so that you can use the CLI.
Most options can be set from:
* environment variables
* command line flags
* Interactive (username and password only)
"""


class Aws_Tokens(LoggingApp):

    ms_apps_url = "".join([
        'https://account.activedirectory.windowsazure.com',
        '/responsiveapplications/list'
    ])
    REGION_MAP = {
        'we1': 'eu-west-1',
        'wu2': 'us-east-2'
    }
    headers = {'User-Agent': " ".join([
        'Mozilla/5.0 (Macintosh;',
        'Intel Mac OS X 10_13_2)',
        'AppleWebKit/537.36',
        '(KHTML, like Gecko)',
        'Chrome/68.0.3440.106',
        'Safari/537.36'])
    }
    blacklist = [
        'response_mode',
        None
    ]
    r = requests.Session()
    config = configparser.RawConfigParser()
    c = None
    assertion = None
    roles = None
    apps = None
    login = None
    last_host = None

    def get_config(self):
        if not self.params.username:
            self.params.username = input('Username: ')
        if not self.params.password:
            self.params.password = getpass.getpass()
        try:
            self.log.info("Loading AWS Config from {loc}".format(
                loc=self.params.config
            ))
            self.config.read(self.params.config)
        except Exception:
            self.log.warning("Creating New Config at {loc}".format(
                loc=self.params.config
            ))
        return self.config

    def write_config(self, config):
        c = self.params.config
        awscredsdir = os.path.dirname(c)
        cred_file = str(c).replace(awscredsdir, '')
        self.log.debug("AWS Creds Dir: " + awscredsdir)
        self.log.debug("AWS Creds File: " + cred_file)
        if awscredsdir == '':
            self.log.debug('Resetting Cred Dir to local')
            awscredsdir = os.getcwd() + os.sep
        if not os.path.exists(awscredsdir):
            self.log.info("Creating Creds Dir: " + str(awscredsdir))
            os.makedirs(awscredsdir)
        c = awscredsdir + cred_file
        try:
            self.log.info("AWS Creds URL: " + c)
            with open(c, 'w') as credsfile:
                config.write(credsfile)
        except IOError as e:
            self.log.error("No File Write: " + str(c))
            self.log.debug(e)
        except Exception as e:
            self.log.error('Something really funky happened!')
            self.log.debug(e)
        return c

    def get_roles(self, resp):
        tree = ElementTree.fromstring(resp)
        attr = './/{urn:oasis:names:tc:SAML:2.0:assertion}Attribute[@Name]'
        av = '{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue'
        att_name = 'https://aws.amazon.com/SAML/Attributes/Role'
        self.roles = []
        for attribute in tree.findall(attr):
            if attribute.attrib['Name'] == att_name:
                for val in attribute.findall(av):
                    provider_arn, role_arn = val.text.split(',')
                    self.roles.append((provider_arn, role_arn))
        return self.roles

    def assume_role(self, config, role, app):
        role_arn = role[0]
        principal_arn = role[1]
        if 'saml-provider' in principal_arn:
            self.log.info("Found SAML Provider in " + principal_arn)
            role = role_arn.split(':')[-1]
            role_name = role.split('/', 1)[1]
            t = None
            try:
                conn = boto3.client('sts')
                t = conn.assume_role_with_saml(
                    RoleArn=role_arn,
                    PrincipalArn=principal_arn,
                    SAMLAssertion=self.assertion
                )['Credentials']
                if self.params.export:
                    self.log.info("Exporting data to screen||pipe")
                    self.output_to_source(t)
                else:
                    self.log.info("Adding to AWS Configuration in Memory")
                    ret = self.add_role_to_config(
                        config,
                        role_name,
                        t
                    )
            except KeyError:
                self.log.error("No Credentials returned from AWS")
            except botocore.exceptions.ClientError as e:
                self.log.error('Could not Assume Role: ' + role_name)
                self.log.debug("Error:" + str(e))
                if 'Expired' in str(e):
                    self.log.info("Attempting to Refresh Token")
                    resp = self.get_saml(app)
                    self.log.debug(resp)
                    self.log.info("Retrying this operation")
                    ret = self.assume_role(config, role, app)
                    self.log.debug("RetryResult:" + str(ret))
                else:
                    self.log.error("You do not have access to " + role_arn)
            except Exception as e:
                self.log.error(e)
        return config

    def add_role_to_config(self, config, role_name, t):
        if not config.has_section(role_name):
            self.log.info("Creating Section in Config for " + role_name)
            config.add_section(role_name)
        self.log.info("Setting Credentials for " + role_name)
        config.set(role_name, 'aws_access_key_id',
                   t['AccessKeyId'])
        config.set(role_name, 'aws_secret_access_key',
                   t['SecretAccessKey'])
        config.set(role_name, 'aws_session_token',
                   t['SessionToken'])
        self.log.error('Added ' + str(role_name))
        if self.params.output:
            self.log.info("Adding output option to " + role_name)
            config.set(role_name, 'output', self.params.output)
        if self.params.region:
            self.log.info("Adding region option to " + role_name)
            config.set(role_name, 'region', self.params.region)
        else:
            self.log.info("Adding automagic region option to " + role_name)
            role_region = self.get_role_region(role_name)
            if role_region:
                config.set(role_name, 'region', role_region)
        return config

    def get_role_region(self, role_name):
        role_region = role_name.lower()[:3]
        self.log.info("Working out Roles Region Code using: {reg}".format(
            reg=role_region
        ))
        r = None
        if role_region in self.REGION_MAP.keys():
            r = self.REGION_MAP[role_region]
            self.log.debug("Region Returned: " + str(r))
        else:
            self.log.debug("No Region Pattern Recognised")
        return r

    def post_to(self, url, data=None):
        self.last_host = '{0.scheme}://{0.netloc}'.format(
            urlparse.urlsplit(url)
        )
        self.log.info("Posting to: {url}".format(
            url=url
        ))
        try:
            data = json.loads(data)
        except Exception:
            pass
        p = {
            'url': url,
            'headers': self.headers,
        }
        if 'SAS' in url and 'ProcessAuth' not in url:
            p['json'] = data
        else:
            p['data'] = dict(data)
        resp = self.r.post(**p)
        aws = 'https://console.aws.amazon.com/console/home'
        if resp.url != url and resp.url != aws:
            r = resp.url.replace('#', '?')
            self.log.info('following post link: {url}'.format(
                url=r
            ))
            resp = self.get_from(r)
        return self.process(resp)

    def get_from(self, url):
        test_url = None
        while url != test_url:
            self.last_host = '{0.scheme}://{0.netloc}'.format(
                urlparse.urlsplit(url)
            )
            self.log.info("Getting from: {url}".format(
                url=url
            ))
            p = {
                'url': url,
                'headers': self.headers
            }
            r = self.r.get(**p)
            test_url = url
            url = r.url
        return self.process(r)

    def process(self, resp):
        ret = None
        try:
            if "window.location = '" in resp.text:
                resp = self.get_from(
                    resp.text.split(
                        "window.location = '", 1
                    )[1].split("';", 1)[0]
                )
                self.log.debug("Found On Load")
        except Exception:
            pass
        try:
            soup = BeautifulSoup(resp.text, features='lxml')
            form = soup.find('form')
            inputs = form.find_all('input')
            payload = {}
            for i in inputs:
                if i.get('name') not in self.blacklist:
                    payload[i.get('name')] = i.get('value')
            url = form.get('action')
            ret = {'url': url, 'payload': payload}
            self.log.info('XML Found')
        except Exception:
            pass
        try:
            ret = json.loads(resp.text)
            self.log.debug("Found JSON Reply")
        except Exception:
            pass
        try:
            ret = json.loads(str(resp.text).split('\n')[1])
            self.log.debug("Found Application JSON Reply")
        except Exception:
            pass
        if ret is None:
            if isinstance(resp, dict):
                ret = resp
                self.log.debug("Found Dict")
            elif isinstance(resp, list):
                ret = resp
                self.log.debug("Found List")
            elif '$Config={"' in resp.text:
                js_conf = resp.text.split("$Config=", 1)[1]
                ret = json.loads(js_conf.split("//]]>", 1)[0][:-2])
                if 'urlSkipMfaRegistration' in resp:
                    self.log.error('MFA Data needed by Microsoft')
                    self.log.error('Log in by Browser to confirm')
                    ret = self.get_from(ret['urlSkipMfaRegistration'])
                    print(ret)
                    quit()
                else:
                    self.log.debug("Found JS Config")
        self.log.debug(ret)
        return ret

    def tumble(self, resp):
            config = {
                "login": self.params.username
            }
            if 'sCtx' in resp.keys():
                config["ctx"] = resp['sCtx']
                config["flowToken"] = resp['sFT']
            elif 'Ctx' in resp.keys():
                config['ctx'] = resp['Ctx']
                config['flowToken'] = resp['FlowToken']
            if 'urlBeginAuth' in resp.keys():
                config['AuthMethodId'] = 'PhoneAppNotification'
                config['Method'] = 'BeginAuth'
                config['SessionId'] = resp['sessionId']
                self.headers.update({
                    "canary": str(resp['canary']),
                    "hpgact": str(resp['hpgact']),
                    "hpgid": str(resp['hpgid']),

                })
                end_url = resp['urlEndAuth']
                url = resp['urlPost']
                resp = self.post_to(
                    resp['urlBeginAuth'],
                    config
                )
                success = False
                index = 1
                config['Method'] = "EndAuth"
                timeout = time.time() + 60*3
                time.sleep(3)
                while success is not True:
                    config.update({
                        "PollCount": str(index),
                        "SessionId": str(resp['SessionId']),
                        "Ctx": str(resp['Ctx']),
                        "FlowToken": str(resp['FlowToken'])
                    })
                    resp = self.post_to(
                        end_url,
                        config
                    )
                    self.log.warning('Waiting for MFA Acceptance')
                    success = resp['Success']
                    index += 1
                    time.sleep(2)
                    if time.time() > timeout:
                        quit("No MFA Catch Found - Killing")
                del self.headers['canary']
                del self.headers['hpgid']
                del self.headers['hpgact']
                config = {
                    'type': 22,
                    'request': resp['Ctx'],
                    'mfaAuthMethod': 'PhoneAppOTP',
                    'login': self.params.username,
                    'flowToken': resp['FlowToken']
                 }
            elif 'urlSkipMfaRegistration' in resp.keys():
                resp = self.get_from(resp['urlSkipMfaRegistration'])
                url = resp['url']
                config = resp['payload']
            elif 'urlPost' in resp.keys():
                url = resp['urlPost']
                if resp['urlPost'] == '/common/login':
                    if self.login:
                        quit("Incorrect credentials for {user}".format(
                            user=self.params.username
                        ))
                    config["CookieDisclosure"] = 1
                    config["isFidoSupported"] = "1"
                    config["isOtherIdpSupported"] = "true"
                    config["isRemoteNGCSupported"] = "false"
                    config["checkPhones"] = "false"
                    config["isCookieBannerShown"] = resp[
                        'fShowPersistentCookiesWarning'
                    ]
                    config["loginfmt"] = self.params.username
                    config["login"] = self.params.username
                    config["passwd"] = self.params.password
                    config["country"] = resp['country']
                    config["canary"] = resp['canary']
                    self.login = True
            else:
                if 'url' in resp.keys():
                    url = resp['url']
                    config = resp['payload']
                else:
                    self.log.error(resp)
                    quit('Incorrect credentials for {user}'.format(
                        user=self.params.username
                    ))
            if not url.startswith('http'):
                if url.startswith('.'):
                    url = '/applications' + url[1:]
                url = self.last_host + url
            return self.post_to(url, config)

    def get_apps(self):
        resp = self.get_from(self.ms_apps_url)
        while not isinstance(resp, list):
            resp = self.tumble(resp)
        if not self.apps:
            if self.params.name == 'all':
                self.apps = [
                    {
                        'Data': app,
                        'Name': app['DisplayName'],
                        'URL': '{host}/applications/{suf}'.format(
                            host=self.last_host,
                            suf=app['TileNavigationUrl'].split("'")[1::2][0]
                        )
                    } for app in resp if app['ApplicationKey'] == 'aws'
                ]
            else:
                self.apps = [
                    {
                        'Data': app,
                        'Name': app['DisplayName'],
                        'URL': '{host}/applications/{suf}'.format(
                            host=self.last_host,
                            suf=app['TileNavigationUrl'].split("'")[1::2][0]
                        )
                    } for app in resp if app['ApplicationKey'] == 'aws'
                    and self.params.name in app['DisplayName']
                ]
        return self.apps

    def get_saml(self, app):
        resp = self.get_from(app['URL'])
        while 'SAMLResponse' not in resp['payload']:
            resp = self.tumble(resp)
            while 'payload' not in resp.keys():
                resp = self.tumble(resp)
        self.assertion = resp['payload']['SAMLResponse']
        resp['payload'] = base64.b64decode(resp['payload']['SAMLResponse'])
        self.roles = self.get_roles(resp['payload'])
        return resp

    def output_to_source(self, t):
        try:
            signal.signal(signal.SIGPIPE, signal.SIG_DFL)
        except Exception as e:
            self.log.info("Could not set up pipe to source!")
            self.log.debug(str(e))
        aaki = "AWS_ACCESS_KEY_ID={AccessKeyId}".format(**t)
        asak = "AWS_SECRET_ACCESS_KEY={SecretAccessKey}".format(**t)
        ast = "AWS_SESSION_TOKEN={SessionToken}".format(**t)
        quit(aaki + asak + ast + ";")

    def main(self):   # pylint: disable=E0202
        self.log.warning("Starting AWS Token Collection from AAD")
        config = self.get_config()
        self.log.warning("Getting Azure AWS Applications")
        apps = self.get_apps()
        if len(apps) > 0:
            for app in apps:
                self.log.warning('Getting Roles from {app} Application'.format(
                    app=app['Name']
                ))
                self.get_saml(app)
                for r in self.roles:
                    if self.params.role in r[0] or self.params.role == 'all':
                        self.log.info('Getting {r0} tokens using {r1}'.format(
                            r0=r[0],
                            r1=r[1]
                        ))
                        config = self.assume_role(config, r, app)
            if len(self.roles) > 0:
                self.log.warning('Writing Credentials to config')
                self.write_config(config)
                self.log.warning('AWS Tokens run Completed!')
            else:
                quit('ERROR - No AWS Roles Found!')
        else:
            quit('ERROR - No AWS Applications Found on your Profile!')


def awsGetTokens():
    tokens = Aws_Tokens(
        name="AWS Credentials",
        message_format='%(asctime)s [%(filename)s:%(lineno)s] - %(message)s',
        description=DESCRIPTION
    )
    tokens.add_param(
        '-n',
        '--name',
        default=os.getenv(
            'AZURE_APP_NAME',
            'all'
        ),
        help="Azure Application ID or Path",
        action='store'
    )
    tokens.add_param(
        '-u',
        '--username',
        default=os.getenv(
            'USER_NAME',
            None
        ),
        help='username to autheticate against SSO server with',
        action='store'
    )
    tokens.add_param(
        '-c',
        '--config',
        default=os.getenv(
            'AWS_CREDENTIALS_FILE',
            os.path.expanduser("~") + "/.aws/credentials"
        ),
        help='Configuration file to hold AWS Tokens',
        action='store'
    )
    tokens.add_param(
        '-p',
        '--password',
        default=os.getenv(
            'PASSWORD',
            None
        ),
        help='Password to authenticate with',
        action='store'
    )
    tokens.add_param(
        '-r',
        '--role',
        default=os.getenv(
            'AWS_ROLE_NAME',
            'all'
        ),
        help='AWS role to extract (defaults to all available roles)',
        action='store'
    )
    tokens.add_param(
        '--output',
        action='store',
        default=None,
        required=False,
        help='how the AWS profile should output',
    )
    tokens.add_param(
        '--region',
        action='store',
        default=None,
        required=False,
        help='Which regions the script should operate in',
    )
    tokens.add_param(
        '--export',
        action='store_true',
        default=None,
        required=False,
        help="export a single role to current",
    )
    tokens.run()


if __name__ == "__main__":
    awsGetTokens()
