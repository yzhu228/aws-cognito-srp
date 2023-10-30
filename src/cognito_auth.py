'''
This module performs user authentication with USER_SRP_AUTH flow
'''
import binascii
import hmac
import hashlib
import datetime as dt
import base64
import boto3
import boto3.session
import srp
#import re

import warrant.aws_srp as warrant

bytes_to_hex = lambda x: "".join("{:02x}".format(c) for c in x)

# https://github.com/aws/amazon-cognito-identity-js/blob/master/src/AuthenticationHelper.js#L22
n_hex = 'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1' \
        + '29024E088A67CC74020BBEA63B139B22514A08798E3404DD' \
        + 'EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245' \
        + 'E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED' \
        + 'EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D' \
        + 'C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F' \
        + '83655D23DCA3AD961C62F356208552BB9ED529077096966D' \
        + '670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B' \
        + 'E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9' \
        + 'DE2BCBF6955817183995497CEA956AE515D2261898FA0510' \
        + '15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64' \
        + 'ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7' \
        + 'ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B' \
        + 'F12FFA06D98A0864D87602733EC86A64521F2B18177B200C' \
        + 'BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31' \
        + '43DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF'
# https://github.com/aws/amazon-cognito-identity-js/blob/master/src/AuthenticationHelper.js#L49
g_hex = '2'

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

srp_user = srp.User(username, password, hash_alg=srp.SHA256, ng_type=srp.NG_CUSTOM, n_hex=n_hex, g_hex=g_hex )
_, srp_a = srp_user.start_authentication()

srp_a_hex = bytes_to_hex(srp_a)

#auth_parameters = aws_srp.get_auth_params()
auth_parameters = {
   'USERNAME': username,
   'SRP_A': srp_a_hex
}
# Cognito - start the authentication process
response = client.initiate_auth(
   AuthFlow = 'USER_SRP_AUTH',
   AuthParameters = auth_parameters,
   ClientId = client_id,
   ClientMetadata = {
      'UserPoolId': user_pool_id
   }
)

challenges_info = {
   'SALT': binascii.a2b_hex(response['ChallengeParameters']['SALT']),
   'SRP_B': binascii.a2b_hex(response['ChallengeParameters']['SRP_B']),
   'SECRET_BLOCK': response['ChallengeParameters']['SECRET_BLOCK'],
   'USER_ID': response['ChallengeParameters']['USER_ID_FOR_SRP']
}

# process Cognito challenge to obtain session key
session_key = srp_user.process_challenge(challenges_info['SALT'], challenges_info['SRP_B'])
M = aws_srp.get_password_authentication_key(username, password, \
    warrant.hex_to_long(response['ChallengeParameters']['SRP_B']), \
    response['ChallengeParameters']['SALT'])

print(f'Result session_key={binascii.b2a_base64(session_key, newline=False).decode()}')
print(f'Result M={binascii.b2a_base64(session_key, newline=False).decode()}')

now = dt.datetime.utcnow()
now_str = now.strftime('%a %b %d %H:%M:%S UTC %Y')
print(f'Timestamp for challenge: {now_str}')


secret_block_bytes = base64.standard_b64decode(challenges_info['SECRET_BLOCK'])

hmac_obj = hmac.new(M, digestmod=hashlib.sha256)
hmac_obj.update(user_pool_id.split('_')[1].encode('utf-8'))
hmac_obj.update(challenges_info['USER_ID'].encode('utf-8'))
hmac_obj.update(secret_block_bytes)
hmac_obj.update(now_str.encode('utf-8'))

challenges_response = {
   'TIMESTAMP': now_str,
   'USERNAME': challenges_info['USER_ID'],
   'PASSWORD_CLAIM_SECRET_BLOCK': challenges_info['SECRET_BLOCK'],
   'PASSWORD_CLAIM_SIGNATURE': base64.standard_b64encode(hmac_obj.digest()).decode('utf-8')
}

# challenges_response = aws_srp.process_challenge(response['ChallengeParameters'])
# print(challenges_response)
response = client.respond_to_auth_challenge(
   ClientId=client_id,
   ChallengeName='PASSWORD_VERIFIER',
   ChallengeResponses=challenges_response
)
print(response)