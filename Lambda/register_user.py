import json
import boto3
from botocore.exceptions import ClientError
import hashlib
import uuid
import base64
from boto3.dynamodb.conditions import Key

dynamodb = boto3.resource('dynamodb')
s3 = boto3.client('s3')
sns = boto3.client('sns', region_name='us-east-1')

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

def validate_payload(user_data):
    required_fields = ['email', 'password', 'full_name', 'id_card']
    for field in required_fields:
        if field not in user_data:
            return False, f'Missing required field: {field}'
        if not user_data[field]:
            return False, f'Field {field} cannot be empty'
    
    # Additional validation for email, password, and full_name if needed
    if not isinstance(user_data['email'], str) or '@' not in user_data['email']:
        return False, 'Invalid email format'
    if not isinstance(user_data['password'], str) or len(user_data['password']) < 6:
        return False, 'Password must be at least 6 characters long'
    if not isinstance(user_data['full_name'], str):
        return False, 'Full name must be a string'
    
    return True, None

def lambda_handler(event, context):
    table = dynamodb.Table('users')
    user_id_bucket = '5409-users-id-bucket'

    user_data = json.loads(event['body'])
    # Validate payload
    is_valid, error_message = validate_payload(user_data)
    if not is_valid:
        return generate_response(400, error_message)
    
    user_id = str(uuid.uuid4())
    email = user_data['email']
    password = hash_password(user_data['password'])
    full_name = user_data['full_name']
    id_card_base64 = user_data['id_card']

    # Check if a user with the same email already exists
    try:
        response = table.query(
            IndexName='email-index',
            KeyConditionExpression=Key('email').eq(email)
        )
        if response['Items']:
            return generate_response(400, 'User with this email already exists.')
    except ClientError as e:
        return generate_response(500, f'Error checking existing user: {e}')

    try:
        id_card_bytes = base64.b64decode(id_card_base64)
    except base64.binascii.Error as e:
        return generate_response(400, f'Invalid Base 64 string: {e}')
    
    if id_card_bytes[:3] != b'\xff\xd8\xff':
        return generate_response(400, 'Decoded bytes are not a valid JPEG image')
    
    # Upload ID card to S3
    try:
        s3.put_object(Bucket=user_id_bucket, Key=f'{user_id}.jpg', Body=id_card_bytes)
    except ClientError as e:
        return generate_response(500, f'Error uploading ID card: {e}')
    

    # SNS Topic and Subscription Handling
    clean_email = email.split('@')[0]
    topic_name = f"SendVerificationInfoTo-{clean_email}"
    try:
        # Check if an SNS topic with the desired name format exists
        topics_response = sns.list_topics()
        topic_exists = any(topic_name in topic['TopicArn'] for topic in topics_response['Topics'])
    
        if not topic_exists:
            # Create a new SNS topic
            topic_response = sns.create_topic(Name=topic_name)
            topic_arn = topic_response['TopicArn']
            
            # Subscribe the user's email to the newly created topic
            sns.subscribe(
                TopicArn=topic_arn,
                Protocol='email',
                Endpoint=email
            )
        else:
            topic_arn = next(topic['TopicArn'] for topic in topics_response['Topics'] if topic_name in topic['TopicArn'])

            # Check if the email is already subscribed
            subscriptions_response = sns.list_subscriptions_by_topic(TopicArn=topic_arn)
            email_subscribed = any(
                subscription['Endpoint'] == email for subscription in subscriptions_response['Subscriptions'])

            if not email_subscribed:
                # Subscribe the user's email to the existing topic
                sns.subscribe(
                    TopicArn=topic_arn,
                    Protocol='email',
                    Endpoint=email
                )
    
    except ClientError as e:
        return generate_response(500, f'Error handling SNS topic: {e}')
    
    
    # Store user data in DynamoDB
    try:
        table.put_item(
            Item={
                'user_id': user_id,
                'email': email,
                'password': password,
                'full_name': full_name,
                'verification_status': 'Pending'
            }
        )
    
    except ClientError as e:
        return generate_response(500, f'Error saving user data: {e}')

    return generate_response(200, 'Registration successful', {
        'user_id': user_id,
        'email': email,
        'full_name': full_name
    })

