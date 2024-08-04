import json
import boto3
import uuid
import jwt
from datetime import datetime
from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError


SECRET_KEY = "^mw!h*35*mowxzp0n@9-fv2u1h8e*ulqgw=&863q0+bis)je27"

dynamodb = boto3.resource('dynamodb')
TASK_PRIORITY_TYPE_LIST = ['Low', 'Medium', 'High']
TASK_STATUS_LIST = ['ToDo', 'Done']

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

        # Fetch the user's verification status
        table = dynamodb.Table('users')
        response = table.get_item(Key={'user_id': user_id})
        user = response.get('Item')
        if not user:
            return None, generate_response(404, 'User not found')

        verification_status = user.get('verification_status')
        if verification_status != 'Verified':
            return None, generate_response(403, 'User needs to be verified')
        return user_id, None
    except jwt.ExpiredSignatureError:
        return None, generate_response(401, 'Token has expired')
    except jwt.InvalidTokenError:
        return None, generate_response(401, 'Invalid token')
    except ClientError as e:
        return None, generate_response(500, f'Error retrieving user data: {e}')

def check_task_owner(table, task_id, user_id):
    try:
        response = table.get_item(Key={'task_id': task_id})
        existing_task = response.get('Item')
        if not existing_task:
            return generate_response(404, 'Task not found')
        
        if existing_task['user_id'] != user_id:
            return generate_response(403, 'User not authorized')
        
        return None
    except ClientError as e:
        return generate_response(500, f'Error checking task owner: {e}')
    
def validate_task_payload(task_data):
    required_fields = ['title', 'description', 'due_date', 'priority', 'status']
    for field in required_fields:
        if field not in task_data:
            return False, f'Missing required field: {field}'
        if not task_data[field]:
            return False, f'Field {field} cannot be empty'
    
    if task_data['priority'] not in TASK_PRIORITY_TYPE_LIST:
        return False, f'Invalid priority value. Must be one of {TASK_PRIORITY_TYPE_LIST}'
    if task_data['status'] not in TASK_STATUS_LIST:
        return False, f'Invalid status value. Must be one of {TASK_STATUS_LIST}'

    try:
        datetime.fromisoformat(task_data['due_date'])
    except ValueError:
        return False, 'Invalid due_date format. Must be ISO 8601 format (YYYY-MM-DDTHH:MM:SS)'

    return True, None

def lambda_handler(event, context):

    user_id, error_code = validate_auth(event)
    if error_code:
        return error_code

    table = dynamodb.Table('tasks')
    http_method = event['httpMethod']

    query_parameters = event.get('queryStringParameters', {})
    task_id = query_parameters.get('task_id') if query_parameters else None

    if http_method == 'POST':
        return create_task(event, table, user_id)
    elif http_method == 'GET':
        if task_id:
            return get_task_details(event, table, task_id)
        else:
            return list_tasks(event, table, user_id)
    elif http_method == 'PUT':
        return update_task(event, table, user_id)
    elif http_method == 'DELETE':
        return delete_task(event, table, user_id)
    else:
        return generate_response(400, 'Unsupported HTTP method')

def create_task(event, table, user_id):
    task_data = json.loads(event['body'])
    is_valid, validation_error = validate_task_payload(task_data)
    if not is_valid:
        return generate_response(400, validation_error)
    
    task_id = str(uuid.uuid4())
    title = task_data.get('title')
    description = task_data.get('description')
    due_date = task_data.get('due_date')
    priority = task_data.get('priority')
    status = task_data.get('status')
    created_at = datetime.utcnow().isoformat()
    
    try:
        table.put_item(
            Item={
                'user_id': user_id,
                'task_id': task_id,
                'title': title,
                'description': description,
                'due_date': due_date,
                'priority': priority,
                'status': status,
                'created_at': created_at
            }
        )
        return generate_response(200, 'Task created successfully', {
            'task_id': task_id,
            'title': title,
            'description': description,
            'due_date': due_date,
            'priority': priority,
            'status': status,
            'created_at': created_at
        })
    except ClientError as e:
        return generate_response(500, f'Error creating task: {e}')

def list_tasks(event, table, user_id):
    query_params = event.get('queryStringParameters', {})
    priority_filter = query_params.get('priority') if query_params else None
    status_filter = query_params.get('status') if query_params else None

    if (priority_filter and priority_filter not in TASK_PRIORITY_TYPE_LIST) or priority_filter == "":
        priority_filter = None

    if (status_filter and status_filter not in TASK_STATUS_LIST) or status_filter == "":
        status_filter = None

    try:
        response = table.query(
            IndexName='user_id-index',
            KeyConditionExpression=Key('user_id').eq(user_id)
        )
        tasks = response.get('Items', [])
        tasks.sort(key=lambda x: x['created_at'], reverse=True)

        grouped_tasks = {
            'High': [],
            'Medium': [],
            'Low': []
        }

        for task in tasks:
            priority = task.get('priority', 'Medium')  # Default to 'Medium' if not specified when created
            status = task.get('status', 'ToDo')  # Default to 'ToDo' if not specified
            if (priority_filter is None or priority == priority_filter) and (status_filter is None or status == status_filter):
                grouped_tasks[priority].append(task)

        return generate_response(200, 'Tasks fetched successfully', 
                                 {priority_filter: grouped_tasks.get(priority_filter)} if priority_filter else grouped_tasks)
    except ClientError as e:
        return generate_response(500, f'Error retrieving tasks: {e}')

def get_task_details(event, table, task_id):
    try:
        response = table.get_item(Key={'task_id': task_id})
        task = response.get('Item')
        if task:
            return generate_response(200, 'Task fetched successfully', task)
        else:
            return generate_response(404, 'Task not found')
    except ClientError as e:
        return generate_response(500, f'Error retrieving task: {e}')

def update_task(event, table, user_id):
    task_data = json.loads(event['body'])
    task_id = task_data['task_id']

    try:
        error_code = check_task_owner(table, task_id, user_id)
        if error_code:
            return error_code
        
        update_expression = "SET "
        expression_attribute_values = {}
        expression_attribute_names = {}

        if 'title' in task_data:
            if task_data['title'] == "":
                return generate_response(400, f'title field can not be empty')
            update_expression += "#title = :title, "
            expression_attribute_values[':title'] = task_data['title']
            expression_attribute_names['#title'] = 'title'
        if 'description' in task_data:
            if task_data['description'] == "":
                return generate_response(400, f'description field can not be empty')
            update_expression += "#description = :description, "
            expression_attribute_values[':description'] = task_data['description']
            expression_attribute_names['#description'] = 'description'
        if 'due_date' in task_data:
            if task_data['due_date'] == "":
                return generate_response(400, f'due_date field can not be empty')
            update_expression += "due_date = :due_date, "
            expression_attribute_values[':due_date'] = task_data['due_date']
        if 'priority' in task_data:
            if task_data['priority'] not in TASK_PRIORITY_TYPE_LIST:
                return generate_response(400, f'Invalid priority value. Must be one of {TASK_PRIORITY_TYPE_LIST}')
            update_expression += "priority = :priority, "
            expression_attribute_values[':priority'] = task_data['priority']
        if 'status' in task_data:
            if task_data['status'] not in TASK_STATUS_LIST:
                return generate_response(400, f'Invalid status value. Must be one of {TASK_STATUS_LIST}')
            update_expression += "#status = :status, "
            expression_attribute_values[':status'] = task_data['status']
            expression_attribute_names['#status'] = 'status'

        update_expression = update_expression.rstrip(", ")

        if not expression_attribute_values:
            return generate_response(400, 'No valid fields to update')

        table.update_item(
            Key={'task_id': task_id},
            UpdateExpression=update_expression,
            ExpressionAttributeValues=expression_attribute_values,
            ExpressionAttributeNames=expression_attribute_names
        )
        return generate_response(200, 'Task updated successfully')
    except ClientError as e:
        return generate_response(500, f'Error updating task: {e}')

def delete_task(event, table, user_id):
    task_data = json.loads(event['body'])
    task_id = task_data['task_id']

    try:
        error_code = check_task_owner(table, task_id, user_id)
        if error_code:
            return error_code
        
        table.delete_item(Key={'task_id': task_id})
        return generate_response(200, 'Task deleted successfully')
    except ClientError as e:
        return generate_response(500, f'Error deleting task: {e}')

