import json
import boto3
import jwt
from botocore.exceptions import ClientError
from dotenv import load_dotenv
import os

load_dotenv()

session = boto3.session.Session(
    aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
    aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
    aws_session_token=os.getenv("AWS_SESSION_TOKEN")
)

SECRET_KEY = os.getenv("SECRET_KEY")

dynamodb = session.resource('dynamodb')
s3 = session.client('s3')

def generate_response(status_code, message, data=None):
    body = {
        'message': message
    }
    if data:
        body['data'] = data
    return {
        'statusCode': status_code,
        'headers': {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Headers': 'Content-Type',
            'Access-Control-Allow-Methods': 'OPTIONS,POST,GET,PUT,DELETE,PATCH'
        },
        'body': json.dumps(body)
    }

def validate_auth(event):
    auth_header = event['headers'].get('Authorization')
    if not auth_header:
        return None, generate_response(401, 'Missing Authorization header')
    
    token = auth_header.split(' ')[1]
    try:
        decoded_token = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        user_id = decoded_token['user_id']
        return user_id, None
    except jwt.ExpiredSignatureError:
        return None, generate_response(401, 'Token has expired')
    except jwt.InvalidTokenError:
        return None, generate_response(401, 'Invalid token')

def lambda_handler(event, context):
    table = dynamodb.Table('users')
    selfie_bucket = 'users-selfie-bucket'
    id_bucket = 'users-id-bucket'
    
    user_id, code = validate_auth(event)
    if code:
        return code
    
    # Get user details from DynamoDB
    try:
        response = table.get_item(Key={'user_id': user_id})
        if 'Item' not in response:
            return generate_response(404, 'User not found')
        
        user_data = response['Item']
        user_data.pop('password', None)
    except ClientError as e:
        return generate_response(500, f'Error fetching user data: {e}')
    

    # Check if the selfie exists in S3
    try:
        s3.head_object(Bucket=selfie_bucket, Key=f'{user_id}.jpg')
        selfie_url = s3.generate_presigned_url(
            'get_object',
            Params={'Bucket': selfie_bucket, 'Key': f'{user_id}.jpg'},
            ExpiresIn=3600
        )
        user_data['selfie_url'] = selfie_url
    except ClientError as e:
        if e.response['Error']['Code'] == '404':
            user_data['selfie_url'] = None
        else:
            return generate_response(500, f'Error checking selfie existence: {e}')

    # Check if the nid exists in S3
    try:
        s3.head_object(Bucket=id_bucket, Key=f'{user_id}.jpg')
        id_url = s3.generate_presigned_url(
            'get_object',
            Params={'Bucket': id_bucket, 'Key': f'{user_id}.jpg'},
            ExpiresIn=3600
        )
        user_data['id_url'] = id_url
    except ClientError as e:
        if e.response['Error']['Code'] == '404':
            user_data['id_url'] = None
        else:
            return generate_response(500, f'Error checking id existence: {e}')

    return generate_response(200, 'User data retrieved successfully', user_data)


if __name__ == "__main__":
    test_event = {
        "headers": {
            "Authorization": f"Bearer {os.getenv('AUTH_TOKEN')}"
        }
    }
    result = lambda_handler(test_event, None)
    print(result)
