# AWS Tokens #

A Python Module to provide a command line interface to glean tokens from AWS using AAD

# IMPORTANT! #

This script has been developed with the "Push MFA" ability in mind. It cannot accept MFA tokens.
You will need to install the Microsoft Authenticator Application to your phone and get it synced with
your account at https://account.activedirectory.windowsazure.com/securityInfo#/register .

From there you can register your Authenticator as well as "Change Default" to use the "Authenticator app notification"

## Description of Module ##

This is a Python Command Line module backed by pycli, this module has been written to be
called via a standalone mechanism but could be used as part of a bigger library.

### How do I get set up? ###

For using the script you don't need to download the github repo just use pip to install

* $ pip install 'git@github.com/s1l0uk/aws_tokens_from_azure_ad' --process-dependency-links

or download script and extract to a folder and run the following commands from inside the directory

* pip install -r requirements.txt
* pip install .

Otherwise, checkout the repo

* git clone 'git@github.com/s1l0uk/aws_tokens_from_azure_ad'

* or go to the https://github.com/s1l0uk/aws_tokens_from_azure_ad page and download the export

* once downloaded go to the directory and run

* pip install --upgrade . --process-dependency-links


#### To Update the package

if the version of the package has been changed use the following command

* $ pip install 'git@github.com/s1l0uk/aws_tokens_from_azure_ad' --process-dependency-links --force-reinstall --ignore-installed

Otherwise, checkout the repo

* git clone 'git@github.com/s1l0uk/aws_tokens_from_azure_ad'

* or go to the https://github.com/s1l0uk/aws_tokens_from_azure_ad page and download the export

* once downloaded go to the directory and run

* pip install --upgrade . --process-dependency-links

### How do I run tests ###

* $ pip install tox
* $ cd repo/
* $ tox

#### Quick start guide

* $ aws-aad				# get All Tokens with either an interactive session or environment variables

* $ aws-aad -vvvvvvv			# add error reporting -v will give basic reporting add more v for more detail

* $ aws-aad -c"<FILE_NAME>"		# print Token output to a different file

* $ aws-aad -r"<ROLE_NAME>"  		# get A Single Role with either an interactive session or environment variables

* $ aws-aad -a"<app_name>"  		# get ALL roles from a Single Azure Authed AWS Application
	
* $ aws-aad -u"<-adm-xxxxxx-csl>"	# get tokens with username in command line

* $ aws-aad -u"<-adm-xxxxxx-csl>" -p"<password>"  # get tokens with username and password in command line

* $ aws-aad -u"<-adm-xxxxxx-csl>" -p"<password>" -r"<role_name>" # putting it all together  	

* $ aws-aad -u"<-adm-xxxxxx-csl>" -p"<password>" -a"<app_name>" -r"<role_name>" # putting it all together with future single application formation

### Help Menu ###

```
$ aws-aad --help
  -h, --help            show this help message and exit
  -l LOGFILE, --logfile LOGFILE
                        log to file (default: log to stdout)
  -q, --quiet           decrease the verbosity
  -s, --silent          only log warnings
  -v, --verbose         raise the verbosity
  -u USERNAME, --username USERNAME
                        Username to authenticate with
  -c CONFIG, --config CONFIG
                        Configuration file to hold AWS Tokens
  -p PASSWORD, --password PASSWORD
                        Password to authenticate with
  -r ROLE, --role ROLE  AWS role to extract (defaults to all available roles)
  -a APP, --app APP  AWS role to extract (defaults to all available roles)
  --output OUTPUT       how the AWS profile should output
  --region REGION       Which regions the script should operate in
  --export              export a single role to current
```


### FAQ ###
* Q: The script doesn't pick up arguements or errors when a '-' is included
* A1: attach the arguement to the flag (no spaces) which should fix any shell POSIX errors
* A2: USER_NAME and PASSWORD environment variables can be used to set the defaults of the script

* Q: The script doesn't look like it is doing anything... I would like more feedback
* A: Should you feel the script is a little bit slow - you can get more feedback by adding the -vvvv flags (1-many)

* Q: The script is too loud - can we tone the output back
* A: Should you feel the script is a little bit loud - you can use the -s flag to get silent running

* Q: The install command blows up when I run it... something something liburl3 something...
* A: Downgrade the liburl library to something botocore can handle - install awscli or similar has worked for others

