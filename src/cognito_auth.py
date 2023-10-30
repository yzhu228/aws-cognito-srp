'''
This module performs user authentication with USER_SRP_AUTH flow
'''
import boto3
import boto3.session

import warrant.aws_srp as warrant

# These variables should be retrieved from environment variables
username = 'placeholder'
password = 'placeholder'
user_pool_id = 'placeholder'
client_id = 'placeholder'

# use profile_name parameter to specify a profile
# session = boto3.session.Session(profile_name='zhusmelb:dev')
session = boto3.session.Session()

client = session.client('cognito-idp')
aws_srp = warrant.AWSSRP(username=username, password=password, pool_id=user_pool_id, client_id=client_id, client=client)

response = aws_srp.authenticate_user()

print(response['AuthenticationResult']['IdToken'])
