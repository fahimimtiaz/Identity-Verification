import json
import boto3
import jwt
import hashlib
from datetime import datetime, timedelta
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

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

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

def lambda_handler(event, context):
    table = dynamodb.Table('users')

    user_data = json.loads(event['body'])
    email = user_data.get('email')
    password = user_data.get('password')
    if not email or email == "":
        return generate_response(400, 'Email must be provided')
    
    
    if not password or not isinstance(password, str) or len(password) < 6:
        return generate_response(400, 'Valid password must be provided')

    password = hash_password(password)

    try:
        response = table.scan(
            FilterExpression=boto3.dynamodb.conditions.Attr('email').eq(email)
        )
        users = response.get('Items', [])
        if not users or users[0]['password'] != password:
            return generate_response(401, 'Invalid email or password')
        
        user = users[0]
        token = jwt.encode(
            {'email': email, 'user_id': user['user_id'], 'exp': datetime.utcnow() + timedelta(hours=1)},
            SECRET_KEY,
            algorithm='HS256'
        )
        token = token.decode('utf-8')  

        data = {
            'user_id': user['user_id'],
            'email': user['email'],
            'full_name': user['full_name'],
            'verification_status': user['verification_status'],
            'token': token
        }

        return generate_response(200, 'Login successful', data)
    
    except ClientError as e:
        return generate_response(500, f'Error logging in: {e}')

if __name__ == "__main__":
    test_event = {
        "body": json.dumps({
            "email": "xsfahim@gmail.com",
            "password": "testpassword123"
        })
    }
    result = lambda_handler(test_event, None)
    print(result)
