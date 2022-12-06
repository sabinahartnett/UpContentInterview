##S -> indicator that the comment was added by Sabina
import datetime
from time import mktime

from flask import Flask, request #, Response
import jwt
import requests
#import logging 

from secrets import api_auth_token, jwt_secret_key
from utils import parse_date_time
from business import get_user_by_email

app = Flask(__name__)

def clean_widgets(args, list_acceptable = ['type', 'created_start', 'created_end']):
    """
    verify that the parameters of a request are within the list of accepted,
    as well as within the specific user scope
    """
    for arg in args:
        assert arg in list_acceptable
    for possible_arg in list_acceptable:
        if possible_arg not in args:
            args[possible_arg] = None
    if args['created_start'] != None:
        args['created_start'] = parse_date_time(args['created_start'])
    if args['created_end'] != None:
        args['created_end'] = parse_date_time(args['created_end'])
    return args

def create_type_label(raw_type):
    """
    Parses type returned from external API into readible format
    by replacing dashes with spaces and capitalize words
    """
    return ' '.join(word.capitalize() for word in raw_type.split('-'))

def check_date_in_range(created_date, created_start, created_end):
    """
    Check to see if the date passed is within the required range
    """
    if not created_start and not created_end:
        return True
    elif created_start and created_end:
        if created_start <= created_date <= created_end:
            return True
    elif created_start and not created_end:
        if created_start <= created_date:
            return True
    elif created_end and not created_start:
        if created_end >= created_date:
            return True
    return False

def decode_auth_token(auth_token):
    # use jwt, jwt_secret_key
    # should be a one liner, but we want you to see how JWTs work
    ##S depending on which algorithm is used to encode, may need to change that parameter
    return jwt.decode(auth_token, jwt_secret_key) #, algorithms=["HS256"])


def encode_auth_token(user_id, name, email, scopes):
    # use jwt and jwt_secret_key imported above, and the payload defined below
    # should be a one liner, but we want you to see how JWTs work
    # remember to convert the result of jwt.encode to a string
    # make sure to use .decode("utf-8") rather than str() for this
    ##S based on the jwt documentation, looks like the encoded jwt might already be a string:
    ##S https://pyjwt.readthedocs.io/en/stable/usage.html#encoding-decoding-tokens-with-hs256
    payload = {
        'sub': user_id,
        'name': name,
        'email': email,
        'scope': scopes,
        'exp': mktime((datetime.datetime.now() + datetime.timedelta(days=1)).timetuple())
    }
    return jwt.encode(payload, jwt_secret_key).decode("utf-8") #, algorithm="HS256").decode("utf-8")


def get_user_from_token():
    # use decode_auth_token above and flask.request imported above
    # should pull token from the Authorization header
    # Authorization: Bearer {token}
    # Where {token} is the token created by the login route
    ##S this token is an encoded JWT as a bearer token. Returning all user info
    return decode_auth_token(request.headers.get('Authorization').split()[1]) 

@app.route('/')
def status():
    return 'API Test Is Up'

@app.route('/test', methods=['GET'])
def test():
    return 'API Is Running'


@app.route('/user', methods=['GET'])
def user():
    # get the user data from the auth/header/jwt
    ##S user_info = get_user_by_email(get_user_from_token()['email'])
    user_info = get_user_from_token()

    if user_info:
        return user_info

    else:
        return {
            'user_id': '',
            'name': '',
            'email': ''
        }

@app.route('/login', methods=['POST'])
def login():
    # use use flask.request to get the json body and get the email and scopes property
    # use the get_user_by_email function to get the user data
    # return the encoded json web token as a token property on the json response as in the format below
    # we're not actually validitating a password or anything because that would add unneeded complexity
    
    post_body = request.json
    
    # if not post_body:
    #     logging.error("No post body")
    #     return Response(status=400)

    user = get_user_by_email(post_body['email']) ## assuming email is a UID
    if user:
        return encode_auth_token(user['id'], user['name'], user['email'], post_body['scope'])
    if not user:
        return {
            'token': ''
        }


@app.route('/widgets', methods=['GET'])
def widgets():
    # accept the following optional query parameters (using the the flask.request object to get the query params)
    # type, created_start, created_end
    # dates will be in iso format (2019-01-04T16:41:24+0200)
    # dates can be parsed using the parse_date_time function written and imported for you above
    query_body = request.json
    args = request.args

    # get the user ID from the auth/header
    user_info = get_user_from_token()

    # verify that the token has the widgets scope in the list of scopes
    clean_widgets = verify_token_widgets(args, user_info['scope'])

    # Using the requests library imported above send the following the following request,

    # GET https://us-central1-interview-d93bf.cloudfunctions.net/widgets?user_id={user_id}
    # HEADERS
    # Authorization: apiKey {api_auth_token}
    user_id = get_user_by_email(user_info['email'])['id']
    
    ##S something wtih request.headers.get('Authorization')
    auth_header = {"Authorization": "X-API-Key {}" "{}".format(api_auth_token, request.headers.get('Authorization'))} #this will include the API token and the JWT as a bearer token
    widgets_API = requests.get('https://us-central1-interview-d93bf.cloudfunctions.net/widgets?user_id={user_id}', headers=auth_header).content
    # the api will return the data in the following format

    # [ { "id": 1, "type": "floogle", "created": "2019-01-04T16:41:24+0200" } ]
    # dates can again be parsed using the parse_date_time function
    # filter the results by the query parameters
    matching_items = []
    for widget in widgets_API:
        if widget['type'] in user_info['scope'] and check_date_in_range(parse_date_time(widget['created']), args['created_start'], args['created_end']):
            matching_items.append({'id': widget['id'], 'type': widget['type'], "type_label": create_type_label(widget['type']), "created": parse_date_time(widget['created'])})

    # return the data in the format below
    return {
        'total_widgets_own_by_user': len(widgets_API)
        'matching_items': matching_items
    }
    # return {
    #     'total_widgets_own_by_user': 2,
    #     'matching_items': [
    #         {
    #             "id": 0,
    #             "type": "foo-bar",
    #             "type_label": "Foo Bar",  # replace dashes with spaces and capitalize words
    #             "created": datetime.datetime.now().isoformat(), # remember to replace
    #         }
    #     ]
    # }


if __name__ == '__main__':
    app.run()
