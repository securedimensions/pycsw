# =================================================================
#
# Authors: Tom Kralidis <tomkralidis@gmail.com>
#
# Copyright (c) 2021 Tom Kralidis
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

from copy import deepcopy
import logging

from pycsw.ogc.api.util import yaml_load

LOGGER = logging.getLogger(__name__)


def gen_oapi(config, oapi_filepath):
    """
    Genrate OpenAPI document

    :param config: configuration
    :param oapi_filepath: path to base OpenAPI records schema

    :returns: `dict` of OpenAPI document
    """

    oapi = {}

    with open(oapi_filepath, encoding='utf8') as fh:
        oapi = yaml_load(fh)

    LOGGER.debug('Adding tags')
    oapi['tags'] = [{
        'name': 'Capabilities',
        'description': 'essential characteristics of this API'
        }, {
        'name': 'Data',
        'description': 'access to data (records)'
    }]

    LOGGER.debug('Adding parameter components')
    oapi['components']['parameters']['f'] = {
        'name': 'f',
        'in': 'query',
        'description': 'Optional output formats',
        'required': False,
        'schema': {
            'type': 'string',
            'enum': ['json', 'html'],
            'default': 'json'
        },
        'style': 'form',
        'explode': False
    }
    oapi['components']['parameters']['fDCS'] = {
        'name': 'f',
        'in': 'query',
        'description': 'Optional output formats',
        'required': False,
        'schema': {
            'type': 'string',
            'enum': ['json', 'html', 'jose', 'dcs+geo'],
            'default': 'json'
        },
        'style': 'form',
        'explode': False
    }
    oapi['components']['parameters']['keyChallenge'] = {
        'name': 'key_challenge',
        'in': 'query',
        'description': 'PIN for creating a DEK',
        'required': False,
        'schema': {
            'type': 'string'
        },
        'style': 'form',
        'explode': False
    }
    oapi['components']['parameters']['keyChallengeMethod'] = {
        'name': 'key_challenge_method',
        'in': 'query',
        'description': 'method used to produce key_challenge according to RFC 7636',
        'required': False,
        'schema': {
            'type': 'string',
            'enum': ['plain', 'S256'],
            'default': 'plain'
        },
        'style': 'form',
        'explode': False
    }
    oapi['components']['parameters']['publicKeys'] = {
        'name': 'public_keys',
        'in': 'query',
        'description': 'a JSON array of RFC 7515 compliant JWK (JSON Web Key)',
        'required': False,
        'schema': {
            'type': 'string',
            'example': '[{"kid":"LJS","kty":"RSA","n":"23ESdb-5g5QinXwY7QCVNBz5BF_xpZbIxPzwNS7ZWPjfuX9KtMGUbxpw-QmIuUd02k3VbHH95NppDFnzeBoJz9fs8_iBl_VHy6ASYGpbusQ0bHYacpl-cptURQWl7CFvVjkJ7uZtKL-UNKG8cbSG7LT24Ltmk_5Wf6hBPqd_0ml4ZuAq0P_D37FEUXl0NBue6iIGoc6RiZqV0SHqUc4TDMfOxaO_x6Zdy6onjRSgCh_Phs_PWucvmTBVV0nzMpnIi9T_ZCX6m9LGceyF_1ryHourb5idvrdOyozgRM5y4EyxRvfO0dOzevy8eBuliuMIJU7RzBjkQIbWpDAlawKRvQ","e":"AQAB","use":"enc"}]'
        },
        'style': 'form',
        'explode': False
    }
    oapi['components']['parameters']['publicKey'] = {
        'name': 'public_key',
        'in': 'query',
        'description': 'a RFC 7515 compliant JWK (JSON Web Key)',
        'required': False,
        'schema': {
            'type': 'object',
            'example': '{"kid":"LJS","kty":"RSA","n":"23ESdb-5g","e":"AQAB","use":"enc"}'
        },
        'style': 'form',
        'explode': False
    }
    oapi['components']['parameters']['offset'] = {
        'name': 'offset',
        'in': 'query',
        'description': 'The optional offset parameter indicates the index within the result set from which the server shall begin presenting results in the response document.  The first element has an index of 0 (default).',  # noqa
        'required': False,
        'schema': {
            'type': 'integer',
            'minimum': 0,
            'default': 0
        },
        'style': 'form',
        'explode': False
    }
    oapi['components']['parameters']['filter'] = {
        'name': 'filter',
        'in': 'query',
        'description': 'The optional filter parameter specifies a CQL2 expression to be used for enhanced filtering',  # noqa
        'required': False,
        'schema': {
            'type': 'object',
        },
        'style': 'form',
        'explode': False
    }
    oapi['components']['parameters']['vendorSpecificParameters'] = {
        'name': 'vendorSpecificParameters',
        'in': 'query',
        'description': 'Additional "free-form" parameters that are not explicitly defined',  # noqa
        'schema': {
            'type': 'object',
            'additionalProperties': True
        },
        'style': 'form'
    }

    LOGGER.debug('Adding server info')
    oapi['info'] = {
        'contact': {
            'email': config.get('metadata:main', 'contact_email'),
            'name': config.get('metadata:main', 'contact_name'),
            'url': config.get('metadata:main', 'contact_url')
        },
        'version': '1.0',
        'title': config.get('metadata:main', 'identification_title'),
        'description': config.get('metadata:main', 'identification_abstract')
    }

    oapi['servers'] = [{
        'url': config.get('server', 'url'),
        'description': config.get('metadata:main', 'identification_abstract')
    }]

    LOGGER.debug('Adding paths')
    oapi['paths'] = {}

    path = {
        'get': {
            'tags': ['Capabilities'],
            'summary': 'Landing page',
            'description': 'Landing page',
            'operationId': 'getLandingPage',
            'parameters': [
                {'$ref': '#/components/parameters/f'}
            ],
            'responses': {
                '200': {
                    '$ref': '#/components/responses/LandingPage'
                },
                '500': {
                    '$ref': '#/components/responses/ServerError'
                }
            }
        }
    }

    oapi['paths']['/'] = path

    path = {
        'get': {
            'tags': ['Capabilities'],
            'summary': 'Conformance page',
            'description': 'Conformance page',
            'operationId': 'getConformanceDeclaration',
            'parameters': [
                {'$ref': '#/components/parameters/f'}
            ],
            'responses': {
                '200': {
                    '$ref': '#/components/responses/ConformanceDeclaration'
                },
                '500': {
                    '$ref': '#/components/responses/ServerError'
                }
            }
        }
    }

    oapi['paths']['/conformance'] = path

    path = {
        'get': {
            'tags': ['Capabilities'],
            'summary': 'Collections page',
            'description': 'Collections page',
            'operationId': 'getCollections',
            'parameters': [
                {'$ref': '#/components/parameters/f'}
            ],
            'responses': {
                '200': {
                    '$ref': '#/components/responses/Collections'
                },
                '500': {
                    '$ref': '#/components/responses/ServerError'
                }
            }
        }
    }

    oapi['paths']['/collections'] = path

    path = {
        'get': {
            'tags': ['Capabilities'],
            'summary': 'Collection page',
            'description': 'Collection page',
            'operationId': 'getCollectionId',
            'parameters': [
                {'$ref': '#/components/parameters/collectionId'},
                {'$ref': '#/components/parameters/f'}
            ],
            'responses': {
                '200': {
                    '$ref': '#/components/responses/Collection'
                },
                '404': {
                    '$ref': '#/components/responses/NotFound'
                },
                '500': {
                    '$ref': '#/components/responses/ServerError'
                }
            }
        }
    }

    oapi['paths']['/collections/{collectionId}'] = path

    path = {
        'get': {
            'tags': ['Data'],
            'summary': 'Records search items page',
            'description': 'Records search items page',
            'operationId': 'getRecords',
            'security': [{'BearerAuth': ["ogc"]}],
            'parameters': [
                {'$ref': '#/components/parameters/collectionId'},
                {'$ref': '#/components/parameters/bbox'},
                {'$ref': '#/components/parameters/datetime'},
                {'$ref': '#/components/parameters/limit'},
                {'$ref': '#/components/parameters/q'},
                {'$ref': '#/components/parameters/type'},
                {'$ref': '#/components/parameters/externalId'},
                {'$ref': '#/components/parameters/sortby'},
                {'$ref': '#/components/parameters/filter'},
                {'$ref': '#/components/parameters/fDCS'},
                {'$ref': '#/components/parameters/keyChallenge'},
                {'$ref': '#/components/parameters/keyChallengeMethod'},
                #{'$ref': '#/components/parameters/publicKeys'},
                {'$ref': '#/components/parameters/publicKey'},
                {'$ref': '#/components/parameters/offset'},
                {'$ref': '#/components/parameters/vendorSpecificParameters'}
            ],
            'responses': {
                '200': {
                    '$ref': '#/components/responses/Records'
                },
                '400': {
                    '$ref': '#/components/responses/InvalidParameter'
                },
                '401': {
                    '$ref': '#/components/responses/TokenError'
                },
                '404': {
                    '$ref': '#/components/responses/NotFound'
                },
                '500': {
                    '$ref': '#/components/responses/ServerError'
                }
            }
        },
        'post': {
            'tags': ['Data'],
            'summary': 'Publish a Record item page',
            'description': 'Publish a Record item',
            'operationId': 'publishRecord',
            'security': [{'BearerAuth': ["ogc"]}],
            'parameters': [
                {
                    'in': 'path',
                    'name': 'collectionId',
                    'required': True,
                    'schema': {'$ref': '#/components/parameters/collectionId'}
                }
            ],
            'requestBody': {
                'description': 'Record to be published',
                'required': True,
                'content': {
                    'application/xml': {
                        'schema': {
                            'type': 'string'
                        }
                    },
                    'application/json': {
                        'schema': {
                            '$ref': '#/components/schemas/recordGeoJSON'
                        }
                    },
                    'application/jose': {
                        'schema': {
                            'type': 'string'
                        }
                    }
                }
            },
            'responses': {
                '201': {
                    'description': 'Created',
                    'headers': {
                        'Location': {
                             'description': 'URI to the created Record'
                        }
                    }
                },
                '401': {
                    'description': 'Authorization information is missing or invalid.'
                },
                '500': {
                    '$ref': '#/components/responses/ServerError'
                }
            }
        }
    }

    oapi['paths']['/collections/{collectionId}/items'] = path

    path2 =  {
        'get': {
            'tags': ['Data'],
            'summary': 'Records search items page',
            'description': 'Records search items page',
            'operationId': 'getRecords',
            'security': [{'BearerAuth': ["ogc"]}],
            'parameters': [
                {'$ref': '#/components/parameters/collectionId'},
                {'$ref': '#/components/parameters/bbox'},
                {'$ref': '#/components/parameters/datetime'},
                {'$ref': '#/components/parameters/limit'},
                {'$ref': '#/components/parameters/q'},
                {'$ref': '#/components/parameters/type'},
                {'$ref': '#/components/parameters/externalId'},
                {'$ref': '#/components/parameters/sortby'},
                {'$ref': '#/components/parameters/filter'},
                {'$ref': '#/components/parameters/offset'},
                {'$ref': '#/components/parameters/vendorSpecificParameters'}
            ],
            'responses': {
                '200': {
                    '$ref': '#/components/responses/Records'
                },
                '400': {
                    '$ref': '#/components/responses/InvalidParameter'
                },
                '404': {
                    '$ref': '#/components/responses/NotFound'
                },
                '500': {
                    '$ref': '#/components/responses/ServerError'
                }
            }
        }
    }
    path2['get']['operationId'] = 'searchRecords'
    oapi['paths']['/search'] = path2

    f = deepcopy(oapi['components']['parameters']['f'])
    f['schema']['enum'].append('xml')

    path = {
        'get': {
            'tags': ['Data'],
            'summary': 'Records item page',
            'description': 'Records item page',
            'operationId': 'getRecord',
            'security': [{'BearerAuth': ["ogc"]}],
            'parameters': [
                {'$ref': '#/components/parameters/collectionId'},
                {'$ref': '#/components/parameters/recordId'},
                {'$ref': '#/components/parameters/fDCS'},
                {'$ref': '#/components/parameters/keyChallenge'},
                {'$ref': '#/components/parameters/keyChallengeMethod'},
                #{'$ref': '#/components/parameters/publicKeys'},
                {'$ref': '#/components/parameters/publicKey'}
            ],
            'responses': {
                '200': {
                    '$ref': '#/components/responses/Record'
                },
                '401': {
                    'description': 'Authorization information is missing or invalid.'
                },
                '404': {
                    '$ref': '#/components/responses/NotFound'
                },
                '500': {
                    '$ref': '#/components/responses/ServerError'
                }
            }
        },
        'put': {
            'tags': ['Data'],
            'summary': 'Publish a Record item page',
            'description': 'Publish a Record item',
            'operationId': 'putRecord',
            'security': [{'BearerAuth': ["ogc"]}],
            'parameters': [
                {
                    'in': 'path',
                    'name': 'collectionId',
                    'required': True,
                    'schema': {'$ref': '#/components/parameters/collectionId'}
                },
                {
                    'in': 'path',
                    'name': 'recordId',
                    'required': True,
                    'schema': {'$ref': '#/components/parameters/recordId'}
                }
            ],
            'requestBody': {
                'description': 'Record to be published',
                'required': True,
                'content': {
                    'application/xml': {
                        'schema': {
                            'type': 'string'
                        }
                    },
                    'application/json': {
                        'schema': {
                            '$ref': '#/components/schemas/recordGeoJSON'
                        }
                    },
                    'application/jose': {
                        'schema': {
                            'type': 'string'
                        }
                    }
                }
            },
            'responses': {
                '201': {
                    'description': 'Created',
                    'headers': {
                        'Location': {
                             'description': 'URI to the created Record'
                        }
                    }
                },
                '401': {
                     'description': 'Authorization information is missing or invalid.'
                },
                '500': {
                    '$ref': '#/components/responses/ServerError'
                }
            }
        }
    }

    oapi['paths']['/collections/{collectionId}/items/{recordId}'] = path

    return oapi
