import json
import boto3
import jwt
import base64
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
rekognition = session.client('rekognition', region_name='us-east-1')
sns = session.client('sns', region_name='us-east-1')
FACE_MATCHING_THRESHOLD = 80

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
    
def send_email(topic_name, subject, message):
    try:
        # Check if the SNS topic exists
        topics_response = sns.list_topics()
        topic_arn = None
        for topic in topics_response['Topics']:
            if topic_name in topic['TopicArn']:
                topic_arn = topic['TopicArn']
                break
        
        if not topic_arn:
            # Create a new SNS topic
            topic_response = sns.create_topic(Name=topic_name)
            topic_arn = topic_response['TopicArn']
        
        # Publish the message to the SNS topic
        sns.publish(
            TopicArn=topic_arn,
            Subject=subject,
            Message=message
        )
        return topic_arn  # Return the topic ARN to use for deletion
    except ClientError as e:
        return generate_response(500, f'Error sending email: {e}')

def get_user_info(user_id):
    table = dynamodb.Table('users')
    try:
        response = table.get_item(Key={'user_id': user_id})
        item = response.get('Item')
        if item:
            return item.get('email'), item.get('full_name')
        else:
            return None, None
    except ClientError as e:
        return None, None
    
def delete_topic(topic_arn):
    try:
        sns.delete_topic(TopicArn=topic_arn)
    except ClientError as e:
        return generate_response(500, f'Error deleting SNS topic: {e}')
    
def lambda_handler(event, context):
    table = dynamodb.Table('users')
    selfie_bucket = 'users-selfie-bucket'
    id_bucket = 'users-id-bucket'

    user_id, code = validate_auth(event)
    if code:
        return code
    
    user_data = json.loads(event['body'])
    selfie = user_data['selfie']

    try:
        selfie_bytes = base64.b64decode(selfie)
    except base64.binascii.Error as e:
        return generate_response(400, f'Invalid Base 64 string: {e}')
    
    if selfie_bytes[:3] != b'\xff\xd8\xff':
        return generate_response(400, 'Decoded bytes are not a valid JPEG image')
    
    try:
        s3.put_object(Bucket=selfie_bucket, Key=f'{user_id}.jpg', Body=selfie_bytes, ContentType='image/jpeg')
    except ClientError as e:
        return generate_response(500, f'Error uploading selfie: {e}')
    
    # Compare new selfie and ID card using Rekognition
    try:
        
        response = rekognition.compare_faces(
            SourceImage={'S3Object': {'Bucket': selfie_bucket, 'Name': f'{user_id}.jpg'}},
            TargetImage={'S3Object': {'Bucket': id_bucket, 'Name': f'{user_id}.jpg'}},
            SimilarityThreshold=FACE_MATCHING_THRESHOLD
        )

        email, full_name = get_user_info(user_id)
        if not email:
            return generate_response(500, 'User information not found')
        clean_email = email.split('@')[0]
       

        if response['FaceMatches']:
            verification_status = 'Verified'
            # Update verification status in DynamoDB
            table.update_item(
                Key={'user_id': user_id},
                UpdateExpression='SET verification_status = :val',
                ExpressionAttributeValues={':val': verification_status}
            )
            topic_arn = send_email(
                topic_name=f"SendVerificationInfoTo-{clean_email}",
                subject='Congratulations!',
                message=f'Your account has been successfully verified. Welcome, {full_name}!'
            )

            if isinstance(topic_arn, dict):  # If send_email returns an error response
                return topic_arn
            delete_topic(topic_arn)  # Delete the topic after sending the email


            return generate_response(200, 'Verification completed', {
                'verification_status': verification_status
            })
        else:
             send_email(
                topic_name=f"SendVerificationInfoTo-{clean_email}",
                subject='Verification Failed',
                message=f'Your account verification has failed. Please retry by uploading a better selfie that matches with your ID card photo.'
            )
             return generate_response(400, 'Verification failed', {
                'verification_status': 'Pending'
            })
        
    except ClientError as e:
        return generate_response(500, f'Error verifying identity: {e}')


if __name__ == "__main__":
    test_event = {
        "headers": {
            "Authorization": f"Bearer {os.getenv('AUTH_TOKEN')}"
        },
        "body": json.dumps({
            "selfie": os.getenv("SELFIE_BASE64")
        })
    }
    result = lambda_handler(test_event, None)
    print(result)
