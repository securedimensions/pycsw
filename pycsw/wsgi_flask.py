# =================================================================
#
# Authors: Tom Kralidis <tomkralidis@gmail.com>
#          Angelos Tzotsos <tzotsos@gmail.com>
#
# Copyright (c) 2021 Tom Kralidis
# Copyright (c) 2021 Angelos Tzotsos
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation
# files (the "Software"), to deal in the Software without
# restriction, including without limitation the rights to use,
# copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the
# Software is furnished to do so, subject to the following
# conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
# OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
# HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
# OTHER DEALINGS IN THE SOFTWARE.
#
# =================================================================

from configparser import ConfigParser
import os
from pathlib import Path 
import sys

from flask import Flask, Blueprint, make_response, request, Response, send_file, jsonify

from pycsw.core.util import parse_ini_config
from pycsw.ogc.api.records import API
from pycsw.ogc.api.util import STATIC
from pycsw.wsgi import application_dispatcher

from pymemcache.client.base import Client
from functools import wraps, update_wrapper
import json, time, requests, base64, re

from Crypto.Random import get_random_bytes
from jose import jwe, jwk, jws, constants
from jose.constants import ALGORITHMS
from jose.utils import base64url_encode, base64url_decode
from datetime import datetime, timedelta
import time
import uuid
from urllib.parse import unquote

APP = Flask(__name__, static_folder=STATIC, static_url_path='/static')
APP.url_map.strict_slashes = False
APP.config['PYCSW_CONFIG'] = parse_ini_config(Path(os.getenv('PYCSW_CONFIG')))
APP.config['JSONIFY_PRETTYPRINT_REGULAR'] = APP.config['PYCSW_CONFIG']['server'].get(
    'pretty_print', True)
APP.config['PREFERRED_URL_SCHEME'] = 'https'


BLUEPRINT = Blueprint('pycsw', __name__, static_folder=STATIC,
                      static_url_path='/static')

api_ = API(APP.config['PYCSW_CONFIG'])

class JsonSerde(object):
    def serialize(self, key, value):
        if isinstance(value, str):
            return value, 1
        return json.dumps(value), 2

    def deserialize(self, key, value, flags):
       if flags == 1:
           return value
       if flags == 2:
           return json.loads(value)
       raise Exception("Unknown serialization format")
   
def check_access_token(token):
    client_id = APP.config['PYCSW_CONFIG']['oauth'].get('client_id', True)
    print('client_id: ' + client_id)
    client_secret = APP.config['PYCSW_CONFIG']['oauth'].get('client_secret', True)
    print('client_secret: ' + client_secret)
    credentials = base64.b64encode(bytes('{}:{}'.format(client_id,client_secret),'utf-8')).decode('ascii')
    token_url = 'https://www.authenix.eu/oauth/tokeninfo'
    header = {'Authorization': "Basic {}".format(credentials), 'Content-Type': 'application/x-www-form-urlencoded'}
    body = {"token": token}
    #tokeninfo = '{"active": true,"scope": "string","client_id": "string","username": "string","token_type": "string","exp": 0,"iat": 0,"nbf": 0,"sub": "string","aud": "string","iss": "string","jti": "string"}'
    tokeninfo = requests.post(token_url, data=body, headers=header)

    return json.loads(tokeninfo.content)

def validate_access_token(token):
    try:
        client = Client('127.0.0.1', serde=JsonSerde(), ignore_exc=False)
        print(client)
        result = client.get(token)
    except Exception as e:
        print(e)
        False
    now = int(time.time())

    if result is None:
        # The cache is empty, need to get the value
        # from the canonical source:
        result = check_access_token(token)
        if not bool(result['active']):
            return False
    
        # Cache the result for next time:
        client.set(token, result, result['exp'] - now)
        
    return (result['active'] and (now < result['exp']))

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        accepts = ['application/dcs+geo', 'application/jose']
        fs = ['JWE', 'jwe', 'jose', 'dcs+geo']

        if 'Prefer' not in request.headers:
            if ('f' in request.args):
                if (request.args['f'] not in fs):
                    if ('Accept' in request.headers) and (request.headers['Accept'] not in accepts):
                        return f(None, *args, **kwargs)
            else:
                print(request.headers)
                if ('Content-Type' in request.headers):
                    if (request.headers['Content-Type'] not in accepts):
                        print("1")
                        return f(None, *args, **kwargs)
                else:
                    print("2")
                    if ('Accept' in request.headers) and (request.headers['Accept'] not in accepts):
                        print("3")
                        return f(None, *args, **kwargs)

        if 'Authorization' in request.headers:
                auth_header = request.headers['Authorization']
                if re.compile('^[Bb]earer\s{1}.+$').match(auth_header):
                    token = auth_header.split()[1]
        else:
                token = request.args.get('access_token', '')
                    
        if not token:
                return {"code": "401", "description": "Access Token missing"}, 401
    
        try:
                result = validate_access_token(token)
                if not result:
                    return {"code": "400", "description": "Access Token invalid"}, 400
        except:
                return {"code": "401", "description": "Access Token invalid"}, 401
        
        return f(token, *args, **kwargs)

    return decorated

def validate_qs_arguments():
    def decorator(f):
        accepts=["application/dcs+geo","application/jose"]
        fs=["JWE","jwe","jose", "dcs+geo"]
        key_challenge = None
        
        print("validating arguments")
        def wrapped_function(*args, **kwargs):
            if ('f' in request.args):
                if (request.args['f'] not in fs):
                    if ('Accept' in request.headers) and (request.headers['Accept'] not in accepts):
                        return f(None, None, None, *args, **kwargs)
            else:
                if ('Accept' in request.headers) and (request.headers['Accept'] not in accepts):
                        return f(None, None, None, *args, **kwargs)

            if request.args.get('key_challenge') is None and request.args.get('public_keys') is None and request.args.get('public_key') is None:
                return {"code": "400", "description": "'key_challenge' or 'public_keys' or 'public_key' parameter must be used"}, 400

            # public_key has precedence
            if request.args.get('public_key') is not None:
                arg = request.args.get('public_key')
                public_key = {}
                items = iter(arg.split(","))
                for item in items:
                    public_key.update({item: next(items)})
                
                return f(None, None, [public_key], *args, **kwargs)

            # public_keys is next
            if request.args.get('public_keys') is not None:
                public_keys = request.args.get('public_keys')
                public_keys = unquote(public_keys)
                public_keys = json.loads(public_keys)
                if len(public_keys) > 1:
                    return {"code": "400", "description": "only support size=1 for 'public_keys' "}, 400
                
                return f(None, None, public_keys, *args, **kwargs)

            # then direct encryption with key_challenge                
            if request.args.get('key_challenge') is None:
                return {"code": "400", "description": "'{name}' parameter is missing".format(name='key_challenge')}, 400
            else:
                key_challenge = request.args.get('key_challenge')
            
            if request.args.get('key_challenge_method'):
                key_challenge_method = request.args.get('key_challenge_method')
            else:
                key_challenge_method = 'plain'
                        
            return f(key_challenge, key_challenge_method, None, *args, **kwargs)
        return update_wrapper(wrapped_function, f)
    return decorator

def json2record(data):
    record = json.loads(data)
    id = record['id']
    properties = record['properties']
    type = properties['type']
    abstract = properties['description']
    if 'extent' in properties:
        spatial = properties['extent']['spatial']
        crs = spatial['crs']
        bbox = spatial['bbox']
        data = """<?xml version="1.0" encoding="UTF-8"?>
        <csw:Record xmlns:csw="http://www.opengis.net/cat/csw/2.0.2" 
            xmlns:ows="http://www.opengis.net/ows" 
            xmlns:dc="http://purl.org/dc/elements/1.1/" 
            xmlns:dct="http://purl.org/dc/terms/">
            <dc:identifier>{}</dc:identifier>
            <dc:type>{}</dc:type>
            <dct:abstract>{}</dct:abstract>
           <ows:BoundingBox crs="{}">
                <ows:LowerCorner>{} {}</ows:LowerCorner>
                <ows:UpperCorner>{} {}</ows:UpperCorner>
            </ows:BoundingBox>
        </csw:Record>
        """.format(id, type, abstract, crs, bbox[0][0], bbox[0][1], bbox[0][2], bbox[0][3])
    else:
        data = """<?xml version="1.0" encoding="UTF-8"?>
        <csw:Record xmlns:csw="http://www.opengis.net/cat/csw/2.0.2" 
            xmlns:ows="http://www.opengis.net/ows" 
            xmlns:dc="http://purl.org/dc/elements/1.1/" 
            xmlns:dct="http://purl.org/dc/terms/">
            <dc:identifier>{}</dc:identifier>
            <dc:type>{}</dc:type>
            <dct:abstract>{}</dct:abstract>
        </csw:Record>
        """.format(id, type, abstract)
        
    return data.encode('utf-8')
     

def get_response(result: tuple):
    """
    Creates a Flask Response object and updates matching headers.

    :param result:  The result of the API call.
                    This should be a tuple of (headers, status, content).
    :returns:       A Response instance.
    """

    headers, status, content = result

    response = make_response(content, status)

    if headers:
        response.headers = headers
    return response

def create_key(token, key_challenge, key_challenge_method):
    client = Client('127.0.0.1', serde=JsonSerde())
    token_info = client.get(token)

    # create JWK 
    key_secret = get_random_bytes(32)
    key_algorithm = 'A256GCM'
    k = base64url_encode(key_secret).replace(b"=", b"")
    key = jwk.construct(key_secret, key_algorithm)
    
    jwt_valid_seconds = 300
    expires = round(time.time()) + jwt_valid_seconds

    # key_data = json.loads(key.export())
    key_data = {}
    key_data['alg'] = key_algorithm
    key_data['k'] = k
    key_data['kty'] = 'oct'
    key_data['key_challenge'] = key_challenge
    key_data['key_challenge_method'] = key_challenge_method
    key_data['expires'] = expires
    #key_data['audience'] = '019b7173-a9ed-7d9a-70d3-9502ad7c0575'
    key_data['aud'] = token_info['client_id']
    key_data['issuer'] = 'https://ogc.demo.secure-dimensions.de/pycsw'
    
    key_url = 'https://ogc.demo.secure-dimensions.de/kms/dek'
    header = {'Authorization': "Bearer {}".format(token), 'Content-Type': 'application/x-www-form-urlencoded'}
    #key_info = requests.post(key_url, data=key_data, headers=header)
    #registered_key = json.loads(key_info.content)
    #kid = registered_key['kid']
    while True:
        kid = str(uuid.uuid4())
        key_data['kid'] = kid
        key_data['kurl'] = key_url + '/' + kid
        key_info = requests.put(key_url + '/' + kid, data=key_data, headers=header)
        if (key_info.status_code != 201):
            code = json.loads(key_info.content)['code']
            description = json.loads(key_info.content)['error']['description']
            return {"code": code, "description": "KMS error: " + description}, key_info.status_code
        elif (key_info.status_code == 409):
            continue
        else:
            break

    return key_data

def get_dcs_response(result: tuple, token, key_challenge, key_challenge_method, public_keys):
    """
    Creates a Flask Response object and updates matching headers.

    :param result:  The result of the API call.
                    This should be a tuple of (headers, status, content).
    :returns:       A Response instance.
    """

    headers, status, content = result

    """
    Encrypt the response using JWE
    """
    if public_keys is not None:
        for public_key in public_keys:
            encrypted_content = jwe.encrypt(content, public_key, algorithm='RSA-OAEP', encryption='A128GCM', kid=public_key['kid'], cty='geo+json').decode('utf-8')
    else:       
        key_data = create_key(token, key_challenge, key_challenge_method)
        key_secret = base64url_decode(key_data['k'])
        encrypted_content = jwe.encrypt(content, key_secret, algorithm='dir', encryption=key_data['alg'], kid=key_data['kid'], cty='geo+json', additional_headers={'kurl': key_data['kurl'], 'crit': ['kurl']}).decode('utf-8')

    print(content)
    content_dict = json.loads(content)
    confidentiality_information = {'policy_identifier': 'TB18', 'classification': 'unclassified'}
    now = datetime.now().astimezone().replace(microsecond=0).isoformat()

    if 'Feature' == content_dict['type']:
        properties = content_dict['properties']
        last_updated = properties['recordUpdated']
        if 'extent' in properties.keys():
            bbox = properties['extent']['spatial']
        else:
            bbox = []
        if 'description' in properties.keys():
            description = properties['description']
        else:
            description = ''
        if 'links' in content_dict.keys():
            links = content_dict['links']
        else:
            links = []
        number_matched = 1
        number_returned = 1

    if 'FeatureCollection' == content_dict['type']:
        links = content_dict['links']
        del content_dict['links']
        number_matched = content_dict['numberMatched']
        number_returned = content_dict['numberReturned']
        bbox = []

    dcs_geo = {
            'type': 'dcs+geo', 
            'timestamp': now,
            'objects': [
                {
                    'metadata': {'confidentiality_information': confidentiality_information, 'creation_data_time': now, 'number_matched': number_matched, 'number_returned': number_returned, 'bbox': bbox, 'links': links},
                    'data' : encrypted_content
                }
            ]
            }


    #clear_text = jwe.decrypt(encrypted_content,urlsafe_b64decode(key_data['k'] + b"=="))

    print(dcs_geo)
    return json.dumps(dcs_geo), 200, {'Content-Type': 'application/dcs+geo'}
    #print(encrypted_content)
    #return encrypted_content, 200, {'Content-Type': 'application/dcs+geo'}


def get_jwe_response(result: tuple, token, key_challenge, key_challenge_method, public_keys):
    """
    Creates a Flask Response object and updates matching headers.

    :param result:  The result of the API call.
                    This should be a tuple of (headers, status, content).
    :returns:       A Response instance.
    """

    headers, status, content = result

    """
    Encrypt the response using JWE
    """
    if public_keys is not None:
        for public_key in public_keys:
            encrypted_content = jwe.encrypt(content, public_key, algorithm='RSA-OAEP', encryption='A128GCM', kid=public_key['kid'], cty='geo+json').decode('utf-8')
    else:       
        key_data = create_key(token, key_challenge, key_challenge_method)
        key_secret = base64url_decode(key_data['k'])
        encrypted_content = jwe.encrypt(content, key_secret, algorithm='dir', encryption=key_data['alg'], kid=key_data['kid'], cty='geo+json', additional_headers={'kurl': key_data['kurl'], 'crit': ['kurl']}).decode('utf-8')

    #clear_text = jwe.decrypt(encrypted_content,urlsafe_b64decode(key_data['k'] + b"=="))

    print(encrypted_content)
    return encrypted_content, 200, {'Content-Type': 'application/jose'}

def get_jws_response(result: tuple):
    """
    Creates a Flask Response object and updates matching headers.

    :param result:  The result of the API call.
                    This should be a tuple of (headers, status, content).
    :returns:       A Response instance.
    """

    headers, status, content = result

    """
    Sign the response using JWS
    """
    private_key_file = APP.config['PYCSW_CONFIG']['jwks'].get('private_key_file', True)
    with open(private_key_file, "rb") as pemfile: 
        private_key = jwk.construct(pemfile.read(),"RS256")
        print(private_key)

        public_key = jwk.get_key('RS256').public_key(private_key).to_dict()
        public_key['kid'] = 'catalog-sign-key'
        print(public_key)

        header = {
            "iss": "https://ogc.demo.secure-dimensions.de",
            "alg": "RS256",
            "kid": "catalog-sign-key",
            "cty": "geo+json",
            "jwk": public_key,
            "jku": "https://ogc.demo.secure-dimensions.de/.well-known/jwks.json"
        }

        print(content)
        signed_content = jws.sign(content.encode('utf-8'), private_key, headers=header, algorithm=ALGORITHMS.RS256)

        print(signed_content)
        return signed_content, 200, {'Content-Type': 'application/jose'}

    return {"code": "500", "description": "signature file not found"}, 500


@BLUEPRINT.route('/')
def landing_page():
    """
    OGC API landing page endpoint

    :returns: HTTP response
    """

    return get_response(api_.landing_page(dict(request.headers), request.args))


@BLUEPRINT.route('/openapi')
def openapi():
    """
    OGC API OpenAPI document endpoint

    :returns: HTTP response
    """

    return get_response(api_.openapi(dict(request.headers), request.args))


@BLUEPRINT.route('/conformance')
def conformance():
    """
    OGC API conformance endpoint

    :returns: HTTP response
    """

    return get_response(api_.conformance(dict(request.headers), request.args))


@BLUEPRINT.route('/collections')
def collections():
    """
    OGC API collections endpoint

    :returns: HTTP response
    """

    return get_response(api_.collections(dict(request.headers), request.args))


@BLUEPRINT.route('/collections/<collection>')
def collection(collection='metadata:main'):
    """
    OGC API collection endpoint

    :param collection: collection name

    :returns: HTTP response
    """

    return get_response(api_.collection(dict(request.headers),
                        request.args, collection))


@BLUEPRINT.route('/collections/<collection>/queryables')
def queryables(collection='metadata:main'):
    """
    OGC API collection queryables endpoint

    :param collection: collection name

    :returns: HTTP response
    """

    return get_response(api_.queryables(dict(request.headers), request.args,
                        collection))

@BLUEPRINT.route('/search', methods=['GET', 'POST'])
def search(collection='metadata:main'):
    """
    OGC API collection items endpoint
    STAC API items search endpoint

    :param collection: collection name

    :returns: HTTP response
    """

    stac_item = False

    if 'search' in request.url_rule.rule:
        stac_item = True

    return get_response(api_.items(dict(request.headers),
                        request.get_json(silent=True), dict(request.args),
                        collection, stac_item))


@BLUEPRINT.route('/collections/<collection>/items', methods=['GET'])
@validate_qs_arguments()
@token_required
def items(token, key_challenge, key_challenge_method, private_keys, collection='metadata:main'):
    """
    OGC API collection items endpoint
    STAC API items search endpoint

    :param collection: collection name

    :returns: HTTP response
    """

    stac_item = False

    if 'search' in request.url_rule.rule:
        stac_item = True

    features = api_.items(dict(request.headers), request.get_json(silent=True), request.args.to_dict(), collection, stac_item)

    if ('f' in request.args):
        if (request.args['f'] == 'dcs+geo'):
            return get_dcs_response(features, token, key_challenge, key_challenge_method, private_keys)

        if (request.args['f'] == 'JWE') or (request.args['f'] == 'jwe') or (request.args['f'] == 'jose'):
            return get_jwe_response(features, token, key_challenge, key_challenge_method, private_keys)

        if (request.args['f'] == 'JWS') or (request.args['f'] == 'jws'):
            return get_jws_response(features)
    else:
        if ('Accept' in request.headers):
            if ('application/dcs+geo' == request.headers['Accept']):
                return get_dcs_response(features, token, key_challenge, key_challenge_method, private_keys)
            if ('application/jose;profile=jws' == request.headers['Accept']):
                return get_jws_response(features)
            if ('application/jose' == request.headers['Accept']):
                return get_jwe_response(features, token, key_challenge, key_challenge_method, private_keys)

    return get_response(features)


@BLUEPRINT.route('/stac/collections/<collection>/items/<item>')
@BLUEPRINT.route('/collections/<collection>/items/<item>', methods=['GET'])
@validate_qs_arguments()
@token_required
def item(token, key_challenge, key_challenge_method, public_keys, collection='metadata:main', item=None):
    """
    OGC API collection items endpoint

    :param collection: collection name
    :param item: item identifier

    :returns: HTTP response
    """

    if request.method == 'GET':
        stac_item = False

        if 'stac' in request.url_rule.rule:
            stac_item = True

        if 'Prefer' in request.headers:
            prefer = request.headers['Prefer']
            print(prefer)
            prefer = prefer.split(';')
            if 'respond-async' in prefer:
                for term in prefer:
                    pref = term.strip()
                    print("term: " + term)
                    kvp = term.split('=')
                    if len(kvp) == 2:
                        subscription_uri = unquote(kvp[1])
                        # could not figure out how to get flask to use the HTTP_X_FORWARDED_PROTO
                        resources_uri = request.url.replace('http://','https://')
                        print("resources-uri: " + resources_uri)
                        print("subscription: " + subscription_uri)

                        res = requests.patch(subscription_uri, json={'resources-uri': resources_uri}, headers={'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'})
                        print("response patch")
                        print(res)
                        if res.status_code == 204:
                            res = requests.patch(subscription_uri, json={'state': 'start'}, headers={'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'})
                            print("response patch status")
                            print(res)
                            if res.status_code == 204:
                                return Response(None, status=202, headers={'Preference-Applied': 'subscription=' + subscription_uri})
                            else:
                                print(res.content)
                

        feature = api_.item(dict(request.headers), request.args, collection, item, stac_item)
        if ('f' in request.args):
            if (request.args['f'] == 'dcs+geo'):
                return get_dcs_response(feature, token, key_challenge, key_challenge_method, public_keys)
            
            if (request.args['f'] == 'JWE') or (request.args['f'] == 'jwe') or (request.args['f'] == 'jose'):
                return get_jwe_response(feature, token, key_challenge, key_challenge_method, public_keys)

            if (request.args['f'] == 'JWS') or (request.args['f'] == 'jws'):
                return get_jws_response(feature)
        else:
            if ('Accept' in request.headers):
                if ('application/dcs+geo' == request.headers['Accept']):
                    return get_dcs_response(feature, token, key_challenge, key_challenge_method, public_keys)
                if ('application/jose;profile=jws' == request.headers['Accept']):
                    return get_jws_response(feature)
                if ('application/jose' == request.headers['Accept']):
                    return get_jwe_response(feature, token, key_challenge, key_challenge_method, public_keys)

        return get_response(feature)

    if request.method == 'POST':
        return "POSTing not yet supported"


@BLUEPRINT.route('/collections/<collection>/items', methods=['POST'])
@token_required
def item_post(token, collection):
    """
    OGC API collection items endpoint

    :param collection: collection name
    :param item: item identifier

    :returns: HTTP response
    """

    stac_item = False

    if 'stac' in request.url_rule.rule:
        stac_item = True

    print(request.data)

    if 'Content-Type' in request.headers:
        content_type = request.headers['Content-Type']
        if content_type == 'application/json':
            data = json2record(request.data)
        elif content_type == 'application/jose':
            data = request.data
            header = '{}=='.format(data.decode('utf-8').split('.')[0])
            header = base64.b64decode(header)
            header = json.loads(header)
            if header['alg'] != 'dir':
                try:
                    private_key = Path('../keys/pycsw-enc.key').read_text()
                    token = jwe.decrypt(data, private_key)
                    print(header['cty'])
                    if header['cty'] == 'xml':
                        data = token
                    else:
                        data = json2record(token)

                    print(data)
                except Exception as e:
                    return make_response(jsonify({'error': str(e)}), 400)
            else:
                return make_response(jsonify({'error': 'dir encryted JWEs are not yet supported'}), 400)
        else:
            data = request.data
        
    result = api_.item_post(dict(request.headers), data, collection)
    return get_response(result)


@BLUEPRINT.route('/collections/<collection>/items/<item>', methods=['PUT'])
@token_required
def item_put(token, collection, item):
    """
    OGC API collection items endpoint

    :param collection: collection name
    :param item: item identifier

    :returns: HTTP response
    """

    stac_item = False

    if 'stac' in request.url_rule.rule:
        stac_item = True
            
    if 'Content-Type' in request.headers:
        content_type = request.headers['Content-Type']
        if content_type == 'application/json':
            data = json2record(request.data)
        elif content_type == 'application/jose':
            try:
                private_key = Path('../keys/pycsw-enc.key').read_text()
                token = jwe.decrypt(request.data, private_key)
                data = json2record(token)
            except Exception as e:
                return make_response(jsonify({'error': str(e)}), 400)
        else:
            data = request.data
        
    result = api_.item_put(dict(request.headers), data, collection, item)
    return get_response(result)

@BLUEPRINT.route('/collections/<collection>/items/<item>', methods=['DELETE'])
@token_required
def item_delete(token, collection, item):
    """
    OGC API collection items endpoint

    :param collection: collection name
    :param item: item identifier

    :returns: HTTP response
    """
    result = api_.item_delete(dict(request.headers), item)
    return '', 204

@BLUEPRINT.route('/csw', methods=['GET', 'POST'])
def csw():
    """
    CSW endpoint

    :returns: HTTP response
    """

    request.environ['PYCSW_IS_CSW'] = True
    status, headers, content = application_dispatcher(request.environ)

    return get_response((headers, status, content))


@BLUEPRINT.route('/opensearch', methods=['GET'])
def opensearch():
    """
    OpenSearch endpoint

    :returns: HTTP response
    """

    request.environ['PYCSW_IS_OPENSEARCH'] = True
    status, headers, content = application_dispatcher(request.environ)

    return get_response((headers, status, content))


@BLUEPRINT.route('/oaipmh', methods=['GET'])
def oaipmh():
    """
    OpenSearch endpoint

    :returns: HTTP response
    """

    request.environ['PYCSW_IS_OAIPMH'] = True
    status, headers, content = application_dispatcher(request.environ)

    return get_response((headers, status, content))


@BLUEPRINT.route('/sru', methods=['GET'])
def sru():
    """
    OpenSearch endpoint

    :returns: HTTP response
    """

    request.environ['PYCSW_IS_SRU'] = True
    status, headers, content = application_dispatcher(request.environ)

    return get_response((headers, status, content))

@BLUEPRINT.route('/.well-known/jwks.json', methods=['GET'])
def jwks():
    jwks_file = APP.config['PYCSW_CONFIG']['jwks'].get('jwks_file', True)
    print(jwks_file)
    if Path(jwks_file).is_file():
        return send_file(jwks_file, mimetype='application/json')
    else:
        return {"code": "500", "description": "JWKS file not found"}, 500

@BLUEPRINT.after_request
def after_request(response):
    if 'Origin' in request.headers:
        response.headers["Access-Control-Allow-Origin"] = "*" # <- You can change "*" for a domain for example "http://localhost"
        response.headers["Access-Control-Allow-Credentials"] = "true"
        response.headers["Access-Control-Allow-Methods"] = "POST, GET, OPTIONS, PUT, DELETE"
        response.headers["Access-Control-Allow-Headers"] = "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization"
    return response

APP.register_blueprint(BLUEPRINT)

if __name__ == '__main__':
    port = 9000
    if len(sys.argv) > 1:
        port = int(sys.argv[1])
    print(f'Serving on port {port}')
    APP.run(debug=True, host='0.0.0.0', port=port)

    #application.run()



