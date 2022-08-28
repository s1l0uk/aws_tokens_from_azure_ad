from setuptools import setup

reqs = [
    'boto3',
    'bs4',
    'configparser',
    'lxml',
    'pycli',
    'requests',
]

setup(
    name='aad_aws_tokens',
    version='1.0.0',
    description='Manage AWS Tokens from Azure AD',
    author='s1l0uk',
    license='MIT',
    entry_points={
        'console_scripts': [
            'aws-aad' +
            '=' +
            'aws_aad_tokens.aws_tokens:awsGetTokens'
        ],
    },
    packages=[
        "aad_aws_tokens",
    ],
    install_requires=reqs,
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'Topic :: Software Development :: Build Tools',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 2',
    ],
    keywords='AWS-Credentials AzureAD',
)
