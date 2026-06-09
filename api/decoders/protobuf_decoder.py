"""
Protobuf decoder for pRoxy dashboard
Automatically decodes protobuf content from captured traffic
"""

import json
import struct
import logging
from typing import Dict, Any, Optional, Tuple

logger = logging.getLogger("pRoxy.protobuf")

class ProtobufDecoder:
    def __init__(self):
        # Real protobuf schemas based on comprehensive reverse engineering
        # Source: GROK_ENDPOINTS_DECODED.md - Professional API analysis
        self.schemas = {
            'grok.com': {
                'auth_frontend.AuthFrontend': {
                    'GetUser': {
                        'request': {},  # Empty request
                        'response': {
                            1: ('user_id', 'string'),          # UUID string
                            2: ('created_at', 'message'),      # {seconds, nanos}
                            3: ('email', 'string'),
                            4: ('profile_picture_path', 'string'),
                            5: ('first_name', 'string'),
                            6: ('last_name', 'string'),
                            7: ('unknown_field_7', 'string'),
                            8: ('twitter_id', 'string'),
                            12: ('flag_12', 'bool'),
                            13: ('flag_13', 'bool'),
                            15: ('twitter_handle', 'string'),
                            16: ('access_scope', 'string'),
                            18: ('role_level', 'string'),
                            19: ('epoch_data', 'message'),
                            20: ('email_domain', 'string'),
                            21: ('account_type', 'string'),
                            29: ('email_repeated', 'string'),
                            31: ('flag_31', 'bool'),
                            38: ('flag_38', 'bool')
                        }
                    }
                },
                'grok_api.Models': {
                    'ListModes': {
                        'request': {
                            1: ('locale', 'string')  # e.g. 'id-ID'
                        },
                        'response': {
                            1: ('modes', 'repeated_message'),  # mode list
                            2: ('default_mode', 'string')      # 'auto'
                        }
                    }
                },
                'grok_api_v2.Subscriptions': {
                    'GetProductsInfo': {
                        'request': {
                            1: ('platform_flag_1', 'int32'),
                            2: ('platform_flag_2', 'int32')
                        },
                        'response': {
                            1: ('products_info', 'message')
                        }
                    },
                    'GetSubscriptions': {
                        'request': {
                            2: ('request_flag', 'int32')
                        },
                        'response': {
                            7: ('subscription_id_1', 'fixed32'),
                            8: ('subscription_id_2', 'fixed32')
                        }
                    }
                },
                'grok_api.Media': {
                    'ListPipelineTemplates': {
                        'request': {},  # Empty
                        'response': {
                            7: ('user_session_id', 'fixed32'),
                            8: ('pipeline_config', 'fixed32')
                        }
                    }
                },
                'grok_api.Settings': {
                    'GetUserSettings': {
                        'request': {},
                        'response': {
                            1: ('global_flag_1', 'int32'),
                            2: ('global_flag_2', 'message'),
                            3: ('global_flag_3', 'int32'),
                            4: ('global_flag_4', 'int32'),
                            5: ('global_flag_5', 'int32'),
                            6: ('global_flag_6', 'int32'),
                            7: ('global_flag_7', 'int32'),
                            8: ('custom_personas', 'repeated_message'),
                            10: ('global_flag_10', 'int32')
                        }
                    }
                }
            }
        }

    def decode_varint(self, data: bytes, pos: int) -> Tuple[int, int]:
        """Decode protobuf varint"""
        result = 0
        shift = 0

        while pos < len(data):
            if shift >= 64:
                raise ValueError("Varint too long")

            byte = data[pos]
            pos += 1
            result |= (byte & 0x7F) << shift

            if (byte & 0x80) == 0:
                break
            shift += 7

        return result, pos

    def decode_protobuf_fields(self, data: bytes, schema: Optional[Dict] = None) -> Dict[str, Any]:
        """Decode protobuf binary data into fields"""
        if not data:
            return {}

        fields = {}
        pos = 0

        try:
            while pos < len(data):
                if pos >= len(data):
                    break

                # Read field key (field_number << 3 | wire_type)
                key, pos = self.decode_varint(data, pos)
                field_number = key >> 3
                wire_type = key & 0x7

                if wire_type == 0:  # Varint
                    value, pos = self.decode_varint(data, pos)
                    field_name = f"field_{field_number}"
                    field_type = "int32"

                    # Apply schema if available
                    if schema and field_number in schema:
                        field_name, field_type = schema[field_number]
                        if field_type == 'bool':
                            value = bool(value)

                    fields[field_name] = {
                        "value": value,
                        "type": field_type,
                        "wire_type": "varint",
                        "field_number": field_number
                    }

                elif wire_type == 1:  # 64-bit fixed
                    if pos + 8 > len(data):
                        break
                    value = struct.unpack('<Q', data[pos:pos+8])[0]
                    pos += 8

                    field_name = f"field_{field_number}"
                    if schema and field_number in schema:
                        field_name, field_type = schema[field_number]
                    else:
                        field_type = "fixed64"

                    fields[field_name] = {
                        "value": value,
                        "type": field_type,
                        "wire_type": "64-bit",
                        "field_number": field_number
                    }

                elif wire_type == 2:  # Length-delimited (string, bytes, nested message)
                    length, pos = self.decode_varint(data, pos)
                    if pos + length > len(data):
                        break

                    value_bytes = data[pos:pos+length]
                    pos += length

                    field_name = f"field_{field_number}"
                    field_type = "bytes"

                    # Apply schema
                    if schema and field_number in schema:
                        field_name, schema_type = schema[field_number]
                        field_type = schema_type

                    # Try to decode as string
                    if 'string' in field_type.lower():
                        try:
                            value = value_bytes.decode('utf-8')
                            fields[field_name] = {
                                "value": value,
                                "type": "string",
                                "wire_type": "length-delimited",
                                "field_number": field_number
                            }
                        except UnicodeDecodeError:
                            fields[field_name] = {
                                "value": value_bytes.hex(),
                                "type": "bytes",
                                "wire_type": "length-delimited",
                                "field_number": field_number
                            }
                    else:
                        # Try to decode as nested message
                        try:
                            nested_fields = self.decode_protobuf_fields(value_bytes)
                            if nested_fields:
                                fields[field_name] = {
                                    "value": nested_fields,
                                    "type": "message",
                                    "wire_type": "length-delimited",
                                    "field_number": field_number
                                }
                            else:
                                fields[field_name] = {
                                    "value": value_bytes.hex(),
                                    "type": "bytes",
                                    "wire_type": "length-delimited",
                                    "field_number": field_number
                                }
                        except Exception:
                            fields[field_name] = {
                                "value": value_bytes.hex(),
                                "type": "bytes",
                                "wire_type": "length-delimited",
                                "field_number": field_number
                            }

                elif wire_type == 5:  # 32-bit fixed
                    if pos + 4 > len(data):
                        break
                    value = struct.unpack('<I', data[pos:pos+4])[0]
                    pos += 4

                    field_name = f"field_{field_number}"
                    if schema and field_number in schema:
                        field_name, field_type = schema[field_number]
                    else:
                        field_type = "fixed32"

                    fields[field_name] = {
                        "value": value,
                        "type": field_type,
                        "wire_type": "32-bit",
                        "field_number": field_number
                    }

                else:
                    logger.warning(f"Unknown wire type {wire_type} for field {field_number}")
                    break

        except Exception as e:
            logger.error(f"Error decoding protobuf: {e}")

        return fields

    def detect_service_method(self, url: str) -> Tuple[Optional[str], Optional[str]]:
        """Extract service and method from gRPC URL"""
        try:
            if 'grok.com' in url:
                # Extract path like: /auth_frontend.AuthFrontend/GetUser
                path = url.split('grok.com')[-1]
                if '/' in path:
                    parts = path.strip('/').split('/')
                    if len(parts) >= 2:
                        service = parts[0]  # auth_frontend.AuthFrontend
                        method = parts[1]   # GetUser
                        return service, method
                    elif len(parts) == 1:
                        # Handle single part URLs like "_data/v1/app_config"
                        return parts[0], 'GET'
        except Exception as e:
            logger.error(f"Error parsing service method from URL: {e}")

        return None, None

    def decode_flow(self, flow_record) -> Optional[Dict[str, Any]]:
        """Decode protobuf content from a flow record"""
        try:
            url = flow_record.url
            host = flow_record.host

            # Only process gRPC traffic
            if not (host == 'grok.com' or 'grok.com' in url):
                return None

            # Check if this is protobuf content
            content_type = flow_record.request_content_type or ''
            if 'grpc' not in content_type.lower() and 'protobuf' not in content_type.lower():
                return None

            service, method = self.detect_service_method(url)
            if not service or not method:
                return None

            result = {
                "service": service,
                "method": method,
                "url": url,
                "content_type": content_type,
                "request": {},
                "response": {}
            }

            # Get schema for this service/method
            schema_request = None
            schema_response = None

            if host in self.schemas:
                service_schemas = self.schemas[host].get(service, {})
                method_schema = service_schemas.get(method, {})
                schema_request = method_schema.get('request', {})
                schema_response = method_schema.get('response', {})

            # Decode request
            if flow_record.request_body:
                try:
                    # Handle hex-encoded bodies
                    if isinstance(flow_record.request_body, str):
                        # Try to decode as hex
                        try:
                            request_bytes = bytes.fromhex(flow_record.request_body.replace(' ', ''))
                        except ValueError:
                            request_bytes = flow_record.request_body.encode('utf-8')
                    else:
                        request_bytes = flow_record.request_body

                    result["request"] = self.decode_protobuf_fields(request_bytes, schema_request)
                except Exception as e:
                    logger.error(f"Error decoding request: {e}")
                    result["request"] = {"error": str(e)}

            # Decode response
            if flow_record.response_body:
                try:
                    # Handle hex-encoded bodies
                    if isinstance(flow_record.response_body, str):
                        try:
                            response_bytes = bytes.fromhex(flow_record.response_body.replace(' ', ''))
                        except ValueError:
                            response_bytes = flow_record.response_body.encode('utf-8')
                    else:
                        response_bytes = flow_record.response_body

                    result["response"] = self.decode_protobuf_fields(response_bytes, schema_response)
                except Exception as e:
                    logger.error(f"Error decoding response: {e}")
                    result["response"] = {"error": str(e)}

            return result

        except Exception as e:
            logger.error(f"Error in decode_flow: {e}")
            return None

# Global decoder instance
protobuf_decoder = ProtobufDecoder()