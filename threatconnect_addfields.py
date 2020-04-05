#!/usr/bin/env python3

INDICATOR_STANDARD_TYPES = {
    "File": "file",
    "Host": "domain",
    "Address": "ip",
    "URL": "url",
    "ASN": "asn",
    "CIDR": "cidr",
    "emailAddress": "email_address",
    "Mutex": "mutex",
    "Registry Key": "registry",
    "User Agent": "user_agent",
}

INDICATOR_DIAMOND_MAPPING = {
    "File": ["capability"],
    "Host": ["infrastructure"],
    "Address": ["infrastructure"],
    "URL": ["capability", "infrastructure"],
    "ASN": ["infrastructure"],
    "CIDR": ["infrastructure"],
    "EmailAddress": ["infrastructure"],
    "Mutex": ["capability"],
    "Registry Key": ["capability"],
    "User Agent": ["capability"],
}


def add_indicator_diamond_mapping(tc_indicator_data):
    """add diamond_mapping field to TC indicator basic data"""
    diamond = INDICATOR_DIAMOND_MAPPING.get(tc_indicator_data["type"], "")
    tc_indicator_data["diamond_mapping"] = diamond
    return tc_indicator_data


def add_indicator_standard_type(tc_indicator_data):
    """add standard indicator type field to TC indicator basic data"""
    standard_type = INDICATOR_STANDARD_TYPES.get(tc_indicator_data["type"], "")
    tc_indicator_data["type_standard"] = standard_type
    return tc_indicator_data
