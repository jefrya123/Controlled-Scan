# scanner.py
"""
PII Scanner Module - Core detection and classification engine.

This module provides the main functionality for detecting and classifying PII (Personally 
Identifiable Information) using Microsoft Presidio and custom regex patterns. It distinguishes
between "controlled" (US-based) and "non-controlled" (foreign) PII for compliance purposes.

Key Features:
- Microsoft Presidio integration for AI-powered PII detection
- Custom regex patterns for enhanced accuracy
- Smart classification of US vs foreign PII
- Confidence scoring and filtering
- Support for multiple PII types (SSN, email, phone, address, etc.)

Author: PII Scanner Team
Version: 1.0.0
"""

import os
import re
from typing import List, Dict, Any, Optional
from presidio_analyzer import AnalyzerEngine
from presidio_analyzer.nlp_engine import NlpEngineProvider
from regex_patterns import REGEX_PATTERNS


def get_analyzer() -> AnalyzerEngine:
    """
    Initialize and configure the Presidio analyzer engine with custom patterns.
    
    This function sets up the Microsoft Presidio analyzer with:
    - spaCy NLP engine using 'en_core_web_lg' model
    - Custom regex patterns for enhanced detection
    - Higher confidence scores for specific PII types
    
    Returns:
        AnalyzerEngine: Configured Presidio analyzer with custom recognizers
        
    Raises:
        ImportError: If required spaCy model is not installed
        Exception: If analyzer initialization fails
        
    Example:
        >>> analyzer = get_analyzer()
        >>> results = analyzer.analyze(text="My SSN is 123-45-6789", language="en")
    """
    try:
        # Configure NLP engine with spaCy
        provider = NlpEngineProvider(nlp_configuration={
            "nlp_engine_name": "spacy",
            "models": [{"lang_code": "en", "model_name": "en_core_web_lg"}]
        })
        nlp_engine = provider.create_engine()
        analyzer = AnalyzerEngine(nlp_engine=nlp_engine, supported_languages=["en"])
        
        # Add custom regex patterns for enhanced detection
        from presidio_analyzer import Pattern, PatternRecognizer
        
        # Custom SSN pattern with high confidence
        ssn_pattern = Pattern(
            name="ssn_pattern",
            regex=r"\b\d{3}-\d{2}-\d{4}\b",
            score=0.9
        )
        ssn_recognizer = PatternRecognizer(
            supported_entity="US_SSN",
            patterns=[ssn_pattern]
        )
        analyzer.registry.add_recognizer(ssn_recognizer)
        
        # Custom ZIP code pattern
        zip_pattern = Pattern(
            name="zip_pattern",
            regex=r"\b\d{5}(-\d{4})?\b",
            score=0.8
        )
        zip_recognizer = PatternRecognizer(
            supported_entity="US_ZIP",
            patterns=[zip_pattern]
        )
        analyzer.registry.add_recognizer(zip_recognizer)
        
        # Custom US Driver's License patterns with high confidence scores
        # These override default patterns to reduce false positives
        dl_patterns = [
            Pattern(
                name="us_dl_standard",
                regex=r"\b[A-Z]{2}\d{6,7}\b",  # Standard format: AA123456
                score=0.95
            ),
            Pattern(
                name="us_dl_numeric",
                regex=r"\b\d{9}\b",  # Some states use 9 digits
                score=0.9
            ),
            Pattern(
                name="us_dl_letter_numeric",
                regex=r"\b[A-Z]\d{7}\b",  # Some states use 1 letter + 7 digits
                score=0.9
            )
        ]
        dl_recognizer = PatternRecognizer(
            supported_entity="US_DRIVER_LICENSE",
            patterns=dl_patterns
        )
        analyzer.registry.add_recognizer(dl_recognizer)
        
        return analyzer
        
    except ImportError as e:
        raise ImportError(f"Required spaCy model 'en_core_web_lg' not found. "
                         f"Install with: python -m spacy download en_core_web_lg") from e
    except Exception as e:
        raise Exception(f"Failed to initialize Presidio analyzer: {e}") from e


def classify_id(value: str, entity_type: str) -> str:
    """
    Classify identification documents as US (controlled) or foreign (non-controlled).
    
    This function analyzes various national ID formats to determine if they are US-based
    or foreign. It handles multiple ID types including SSNs, driver's licenses, passports,
    and various foreign national ID formats.
    
    Args:
        value (str): The ID value to classify (e.g., "123-45-6789", "AA123456")
        entity_type (str): The Presidio entity type (e.g., "US_SSN", "US_DRIVER_LICENSE")
        
    Returns:
        str: Classification result
            - "controlled": US-based identification (higher compliance concern)
            - "non-controlled": Foreign identification (lower compliance concern)
            - "unknown": Unable to determine classification
            
    Examples:
        >>> classify_id("123-45-6789", "US_SSN")
        'controlled'
        >>> classify_id("AB123456C", "PERSON")
        'non-controlled'  # UK National Insurance Number
        >>> classify_id("123", "US_DRIVER_LICENSE")
        'unknown'  # Too short, likely false positive
    """
    clean_value = value.strip().upper()
    
    # Skip very short values that are likely false positives
    if len(clean_value) < 3:
        return "unknown"
    
    # US-specific IDs (already handled by Presidio entity types)
    # These are automatically classified as controlled since they're US-specific
    if entity_type in ["US_SSN", "US_ITIN", "US_DRIVER_LICENSE", "US_PASSPORT", "CREDIT_CARD"]:
        return "controlled"
    
    # US Passport: 9 digits, starting with 1-9 (not 0)
    us_passport_pattern = r'^[1-9]\d{8}$'
    if re.match(us_passport_pattern, clean_value):
        return "controlled"
    
    # US Driver's License patterns (varies by state but common patterns)
    # Must be at least 6 characters and follow specific patterns
    us_dl_patterns = [
        r'^[A-Z]{2}\d{6,7}$',  # Standard format: AA123456 (8-9 chars)
        r'^\d{9}$',            # Some states use 9 digits
        r'^[A-Z]\d{7}$',       # Some states use 1 letter + 7 digits (8 chars)
    ]
    for pattern in us_dl_patterns:
        if re.match(pattern, clean_value) and len(clean_value) >= 6:
            return "controlled"
    
    # Foreign National IDs - Comprehensive coverage of major countries
    
    # UK National Insurance Number: AB123456C (9 chars, specific format)
    uk_nin_pattern = r'^[A-CEGHJ-NPR-TW-Z]{2}\d{6}[A-D]$'
    if re.match(uk_nin_pattern, clean_value):
        return "non-controlled"
    
    # UK Passport: 9 digits
    uk_passport_pattern = r'^\d{9}$'
    if re.match(uk_passport_pattern, clean_value):
        return "non-controlled"
    
    # Canadian SIN (Social Insurance Number): 123-456-789 (11 chars with dashes)
    canada_sin_pattern = r'^\d{3}-\d{3}-\d{3}$'
    if re.match(canada_sin_pattern, clean_value):
        return "non-controlled"
    
    # Canadian Passport: 2 letters + 6 digits (8 chars)
    canada_passport_pattern = r'^[A-Z]{2}\d{6}$'
    if re.match(canada_passport_pattern, clean_value):
        return "non-controlled"
    
    # German Personalausweis: 9 digits
    germany_id_pattern = r'^\d{9}$'
    if re.match(germany_id_pattern, clean_value):
        return "non-controlled"
    
    # French Carte Nationale d'Identité: 12 digits
    france_id_pattern = r'^\d{12}$'
    if re.match(france_id_pattern, clean_value):
        return "non-controlled"
    
    # Brazilian CPF: 123.456.789-01 (14 chars with dots and dash)
    brazil_cpf_pattern = r'^\d{3}\.\d{3}\.\d{3}-\d{2}$'
    if re.match(brazil_cpf_pattern, clean_value):
        return "non-controlled"
    
    # Indian Aadhaar: 12 digits
    india_aadhaar_pattern = r'^\d{12}$'
    if re.match(india_aadhaar_pattern, clean_value):
        return "non-controlled"
    
    # Japanese My Number: 12 digits
    japan_my_number_pattern = r'^\d{12}$'
    if re.match(japan_my_number_pattern, clean_value):
        return "non-controlled"
    
    # Australian Medicare: 4 digits, space, 5 digits, space, 1 digit
    australia_medicare_pattern = r'^\d{4}\s\d{5}\s\d{1}$'
    if re.match(australia_medicare_pattern, clean_value):
        return "non-controlled"
    
    # Mexican CURP: 18 characters (4 letters, 6 digits, 1 letter, 1 digit, 1 letter, 5 digits)
    mexico_curp_pattern = r'^[A-Z]{4}\d{6}[A-Z]\d[A-Z]\d{5}$'
    if re.match(mexico_curp_pattern, clean_value):
        return "non-controlled"
    
    # Spanish DNI: 8 digits + 1 letter
    spain_dni_pattern = r'^\d{8}[A-Z]$'
    if re.match(spain_dni_pattern, clean_value):
        return "non-controlled"
    
    # Italian Codice Fiscale: 16 characters (6 letters, 2 digits, 1 letter, 2 digits, 1 letter, 3 digits, 1 letter)
    italy_cf_pattern = r'^[A-Z]{6}\d{2}[A-Z]\d{2}[A-Z]\d{3}[A-Z]$'
    if re.match(italy_cf_pattern, clean_value):
        return "non-controlled"
    
    # Default to controlled (US) for ambiguous cases
    # This is a conservative approach - when in doubt, classify as controlled
    return "controlled"


def classify_address(value: str) -> str:
    """
    Smart address classification that distinguishes US vs foreign addresses.
    
    Args:
        value: Address text to classify
        
    Returns:
        "controlled" for US, "non-controlled" for foreign, "unknown" if uncertain
    """
    clean_value = value.strip()
    
    # US ZIP code patterns (5-digit or ZIP+4)
    us_zip_pattern = r'\b\d{5}(-\d{4})?\b'
    if re.search(us_zip_pattern, clean_value):
        return "controlled"
    
    # US state abbreviations (50 states + DC)
    us_states = {
        'AL', 'AK', 'AZ', 'AR', 'CA', 'CO', 'CT', 'DE', 'FL', 'GA',
        'HI', 'ID', 'IL', 'IN', 'IA', 'KS', 'KY', 'LA', 'ME', 'MD',
        'MA', 'MI', 'MN', 'MS', 'MO', 'MT', 'NE', 'NV', 'NH', 'NJ',
        'NM', 'NY', 'NC', 'ND', 'OH', 'OK', 'OR', 'PA', 'RI', 'SC',
        'SD', 'TN', 'TX', 'UT', 'VT', 'VA', 'WA', 'WV', 'WI', 'WY', 'DC'
    }
    
    # Check for US state abbreviations
    words = clean_value.upper().split()
    for word in words:
        if word in us_states:
            return "controlled"
    
    # Foreign postal code patterns
    # UK: W1A 1AA, M1 1AA, B33 8TH
    uk_postcode = r'\b[A-Z]{1,2}\d[A-Z\d]?\s*\d[A-Z]{2}\b'
    if re.search(uk_postcode, clean_value, re.IGNORECASE):
        return "non-controlled"
    
    # Canada: M5V 3A8, H2Y 1C6
    canada_postcode = r'\b[A-Z]\d[A-Z]\s*\d[A-Z]\d\b'
    if re.search(canada_postcode, clean_value, re.IGNORECASE):
        return "non-controlled"
    
    # Australia: 2000, 3000, etc. (4-digit postal codes)
    australia_postcode = r'\b\d{4}\b'
    if re.search(australia_postcode, clean_value):
        # Check if it's not a US ZIP (which would have been caught above)
        # Australian codes are typically 2000-9999
        match = re.search(australia_postcode, clean_value)
        if match:
            code = int(match.group())
            if 2000 <= code <= 9999:
                return "non-controlled"
    
    # Germany: 10115, 20095, etc. (5-digit postal codes)
    germany_postcode = r'\b\d{5}\b'
    if re.search(germany_postcode, clean_value):
        # German codes are typically 01000-99999
        match = re.search(germany_postcode, clean_value)
        if match:
            code = int(match.group())
            if 1000 <= code <= 99999:
                return "non-controlled"
    
    # France: 75001, 13001, etc. (5-digit postal codes)
    france_postcode = r'\b\d{5}\b'
    if re.search(france_postcode, clean_value):
        # French codes are typically 01000-99999
        match = re.search(france_postcode, clean_value)
        if match:
            code = int(match.group())
            if 1000 <= code <= 99999:
                return "non-controlled"
    
    # Japan: 100-0001, 530-0001, etc. (3-digit-4-digit format)
    japan_postcode = r'\b\d{3}-\d{4}\b'
    if re.search(japan_postcode, clean_value):
        return "non-controlled"
    
    # Brazil: 20000-000, 30000-000, etc. (5-digit-3-digit format)
    brazil_postcode = r'\b\d{5}-\d{3}\b'
    if re.search(brazil_postcode, clean_value):
        return "non-controlled"
    
    # India: 110001, 400001, etc. (6-digit postal codes)
    india_postcode = r'\b\d{6}\b'
    if re.search(india_postcode, clean_value):
        return "non-controlled"
    
    # Common foreign address indicators
    foreign_indicators = [
        'street', 'avenue', 'road', 'lane', 'drive', 'close', 'way', 'place',
        'crescent', 'terrace', 'grove', 'mews', 'square', 'court', 'gardens',
        'heath', 'common', 'park', 'hill', 'bridge', 'cross', 'end', 'corner',
        'ruta', 'avenida', 'calle', 'carrera', 'via', 'strada', 'via', 'rue',
        'straße', 'allee', 'platz', 'gasse', 'chemin', 'avenue', 'rue', 'place',
        'rodovia', 'avenida', 'rua', 'travessa', 'praça', 'alameda'
    ]
    
    # Check for foreign address terms
    for indicator in foreign_indicators:
        if indicator.lower() in clean_value.lower():
            # But don't override if we already found US indicators
            if not any(state in clean_value.upper() for state in us_states):
                return "non-controlled"
    
    return "unknown"


def is_partial_email_match(value: str, content: str) -> bool:
    """
    Check if a URL entity is just a partial match from an email address.
    
    Args:
        value: The detected URL value
        content: The full content being scanned
        
    Returns:
        True if it's a partial email match, False otherwise
    """
    clean_value = value.strip().lower()
    
    # Check if this value appears as part of an email address in the content
    email_pattern = rf'\b[A-Za-z0-9._%+-]+@{re.escape(clean_value)}\b'
    if re.search(email_pattern, content, re.IGNORECASE):
        return True
    
    # Check if it's just a common email domain without context
    common_domains = {
        'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'aol.com',
        'icloud.com', 'protonmail.com', 'mail.com', 'live.com', 'msn.com'
    }
    
    if clean_value in common_domains:
        # Look for this domain in email context
        email_context_pattern = rf'\b[A-Za-z0-9._%+-]+@{re.escape(clean_value)}\b'
        if re.search(email_context_pattern, content, re.IGNORECASE):
            return True
    
    return False


def classify_url(value: str) -> str:
    """
    Smart URL classification that distinguishes US vs foreign domains.
    
    Args:
        value: URL value to classify
        
    Returns:
        "controlled" for US, "non-controlled" for foreign
    """
    clean_value = value.strip().lower()
    
    # Skip if it's just a domain from an email (common false positive)
    if '@' in clean_value:
        return "skip"  # Skip partial email matches
    
    # US government and education domains
    us_domains = {
        '.gov', '.mil', '.edu', '.us', '.org', '.net'
    }
    
    # Foreign country domains
    foreign_domains = {
        '.cn', '.ru', '.de', '.fr', '.br', '.uk', '.es', '.it', '.jp', '.kr', 
        '.in', '.au', '.ca', '.mx', '.ar', '.cl', '.pe', '.co', '.ve', '.ec', 
        '.bo', '.py', '.uy', '.gy', '.sr', '.gf', '.fk', '.gs', '.io', '.sh', 
        '.ac', '.tc', '.vg', '.ai', '.ag', '.bb', '.gd', '.lc', '.vc', '.dm', 
        '.kn', '.tt', '.jm', '.ht', '.do', '.pr', '.cu', '.bs', '.bz', '.gt', 
        '.sv', '.hn', '.ni', '.cr', '.pa', '.aw', '.cw', '.bq', '.sx', '.bl', 
        '.mf', '.gp', '.mq', '.yt', '.re', '.sc', '.mu', '.km', '.mg', '.zw', 
        '.na', '.bw', '.ls', '.sz', '.za', '.mz', '.zm', '.mw', '.tz', '.ke', 
        '.ug', '.rw', '.bi', '.dj', '.so', '.et', '.er', '.sd', '.ss', '.cf', 
        '.cg', '.cd', '.ga', '.gq', '.cm', '.st', '.ao', '.gw', '.gn', '.sl', 
        '.lr', '.ci', '.bf', '.ml', '.ne', '.td', '.mr', '.sn', '.gm', '.gn', 
        '.gw', '.cv', '.ma', '.dz', '.tn', '.ly', '.eg', '.sd', '.ss', '.et', 
        '.dj', '.so', '.ke', '.tz', '.ug', '.rw', '.bi', '.mw', '.zm', '.zw', 
        '.na', '.bw', '.ls', '.sz', '.za', '.mz', '.mg', '.km', '.mu', '.sc', 
        '.re', '.yt', '.mq', '.gp', '.bl', '.mf', '.sx', '.bq', '.cw', '.aw', 
        '.pa', '.cr', '.ni', '.hn', '.sv', '.gt', '.bz', '.bs', '.cu', '.pr', 
        '.do', '.ht', '.jm', '.tt', '.kn', '.dm', '.vc', '.lc', '.gd', '.bb', 
        '.ag', '.ai', '.vg', '.tc', '.ac', '.sh', '.io', '.gs', '.fk', '.gf', 
        '.sr', '.gy', '.uy', '.py', '.bo', '.ec', '.ve', '.co', '.pe', '.cl', 
        '.ar', '.mx', '.ca', '.au', '.in', '.kr', '.jp', '.it', '.es', '.uk', 
        '.br', '.fr', '.de', '.ru', '.cn'
    }
    
    # Check for US domains
    for us_domain in us_domains:
        if clean_value.endswith(us_domain):
            return "controlled"
    
    # Check for foreign domains
    for foreign_domain in foreign_domains:
        if clean_value.endswith(foreign_domain):
            return "non-controlled"
    
    # Handle .com domains (could be US or foreign)
    if clean_value.endswith('.com'):
        # Common US company domains
        us_companies = {
            'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'aol.com',
            'apple.com', 'microsoft.com', 'google.com', 'amazon.com', 'facebook.com',
            'twitter.com', 'linkedin.com', 'netflix.com', 'spotify.com', 'uber.com',
            'lyft.com', 'airbnb.com', 'salesforce.com', 'oracle.com', 'ibm.com',
            'intel.com', 'cisco.com', 'adobe.com', 'nvidia.com', 'paypal.com',
            'stripe.com', 'square.com', 'slack.com', 'zoom.us', 'dropbox.com',
            'box.com', 'github.com', 'gitlab.com', 'stackoverflow.com'
        }
        
        if clean_value in us_companies:
            return "controlled"
        else:
            return "controlled"  # Assume US if not known foreign company
    
    # Handle .org domains (usually US-based organizations)
    if clean_value.endswith('.org'):
        return "controlled"
    
    # Handle .net domains (usually US-based)
    if clean_value.endswith('.net'):
        return "controlled"
    
    # Default to controlled (US) for unknown domains
    return "controlled"


def classify_email(value: str) -> str:
    """
    Smart email classification that distinguishes US vs foreign domains.
    
    Args:
        value: Email address to classify
        
    Returns:
        "controlled" for US, "non-controlled" for foreign
    """
    clean_value = value.strip().lower()
    
    # Extract domain from email
    if '@' not in clean_value:
        return "non-controlled"  # Default to non-controlled instead of unknown
    
    # Split email and validate format
    parts = clean_value.split('@')
    if len(parts) != 2:
        return "non-controlled"
    
    local_part, domain = parts
    
    # Basic validation - local part and domain should be reasonable length
    if len(local_part) < 1 or len(domain) < 3:
        return "non-controlled"
    
    # Check for valid domain format (at least one dot)
    if '.' not in domain:
        return "non-controlled"
    
    # US government and education domains (high confidence)
    us_domains = {
        '.gov', '.mil', '.edu', '.us', '.org', '.net'
    }
    
    # Foreign country domains (high confidence)
    foreign_domains = {
        '.cn', '.ru', '.de', '.fr', '.br', '.uk', '.es', '.it', '.jp', '.kr', '.in', '.au', '.ca', '.mx', '.ar', '.cl', '.pe', '.co', '.ve', '.ec', '.bo', '.py', '.uy', '.gy', '.sr', '.gf', '.fk', '.gs', '.io', '.sh', '.ac', '.tc', '.vg', '.ai', '.ag', '.bb', '.gd', '.lc', '.vc', '.dm', '.kn', '.tt', '.jm', '.ht', '.do', '.pr', '.cu', '.bs', '.bz', '.gt', '.sv', '.hn', '.ni', '.cr', '.pa', '.aw', '.cw', '.bq', '.sx', '.bl', '.mf', '.gp', '.mq', '.yt', '.re', '.sc', '.mu', '.km', '.mg', '.zw', '.na', '.bw', '.ls', '.sz', '.za', '.mz', '.zm', '.mw', '.tz', '.ke', '.ug', '.rw', '.bi', '.dj', '.so', '.et', '.er', '.sd', '.ss', '.cf', '.cg', '.cd', '.ga', '.gq', '.cm', '.st', '.ao', '.gw', '.gn', '.sl', '.lr', '.ci', '.bf', '.ml', '.ne', '.td', '.mr', '.sn', '.gm', '.gn', '.gw', '.cv', '.ma', '.dz', '.tn', '.ly', '.eg', '.sd', '.ss', '.et', '.dj', '.so', '.ke', '.tz', '.ug', '.rw', '.bi', '.mw', '.zm', '.zw', '.na', '.bw', '.ls', '.sz', '.za', '.mz', '.mg', '.km', '.mu', '.sc', '.re', '.yt', '.mq', '.gp', '.bl', '.mf', '.sx', '.bq', '.cw', '.aw', '.pa', '.cr', '.ni', '.hn', '.sv', '.gt', '.bz', '.bs', '.cu', '.pr', '.do', '.ht', '.jm', '.tt', '.kn', '.dm', '.vc', '.lc', '.gd', '.bb', '.ag', '.ai', '.vg', '.tc', '.ac', '.sh', '.io', '.gs', '.fk', '.gf', '.sr', '.gy', '.uy', '.py', '.bo', '.ec', '.ve', '.co', '.pe', '.cl', '.ar', '.mx', '.ca', '.au', '.in', '.kr', '.jp', '.it', '.es', '.uk', '.br', '.fr', '.de', '.ru', '.cn'
    }
    
    # Check for US domains
    for us_domain in us_domains:
        if domain.endswith(us_domain):
            return "controlled"
    
    # Check for foreign domains
    for foreign_domain in foreign_domains:
        if domain.endswith(foreign_domain):
            return "non-controlled"
    
    # Handle .com domains (could be US or foreign)
    if domain.endswith('.com'):
        # Common US company domains (not comprehensive, but covers major ones)
        us_companies = {
            'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'aol.com',
            'apple.com', 'microsoft.com', 'google.com', 'amazon.com', 'facebook.com',
            'twitter.com', 'linkedin.com', 'netflix.com', 'spotify.com', 'uber.com',
            'lyft.com', 'airbnb.com', 'salesforce.com', 'oracle.com', 'ibm.com',
            'intel.com', 'cisco.com', 'adobe.com', 'nvidia.com', 'paypal.com',
            'stripe.com', 'square.com', 'slack.com', 'zoom.us', 'dropbox.com',
            'box.com', 'github.com', 'gitlab.com', 'stackoverflow.com'
        }
        
        if domain in us_companies:
            return "controlled"
        else:
            return "controlled"  # Assume US if not known foreign company
    
    # Handle .org domains (usually US-based organizations)
    if domain.endswith('.org'):
        return "controlled"
    
    # Handle .net domains (usually US-based)
    if domain.endswith('.net'):
        return "controlled"
    
    # Default to controlled (US) instead of non-controlled
    return "controlled"


def classify_phone_number(value: str) -> str:
    """
    Smart phone number classification that distinguishes US vs foreign numbers.
    
    Args:
        value: Phone number to classify
        
    Returns:
        "controlled" for US, "non-controlled" for foreign
    """
    clean_value = value.strip()
    
    # US and Canadian area codes
    us_area_codes = {
        '201', '202', '203', '205', '206', '207', '208', '209', '210', '212', '213', '214', '215', '216', '217', '218', '219', '220', '223', '224', '225', '228', '229', '231', '234', '239', '240', '248', '251', '252', '253', '254', '256', '260', '262', '267', '269', '270', '272', '276', '281', '301', '302', '303', '304', '305', '307', '308', '309', '310', '312', '313', '314', '315', '316', '317', '318', '319', '320', '321', '323', '325', '330', '331', '334', '336', '337', '339', '340', '341', '347', '351', '352', '360', '361', '364', '380', '385', '386', '401', '402', '404', '405', '406', '407', '408', '409', '410', '412', '413', '414', '415', '417', '419', '423', '424', '425', '430', '432', '434', '435', '440', '442', '443', '445', '447', '458', '463', '469', '470', '475', '478', '479', '480', '484', '501', '502', '503', '504', '505', '507', '508', '509', '510', '512', '513', '515', '516', '517', '518', '520', '530', '531', '534', '539', '540', '541', '551', '559', '561', '562', '563', '564', '567', '570', '571', '573', '574', '575', '580', '585', '586', '601', '602', '603', '605', '606', '607', '608', '609', '610', '612', '614', '615', '616', '617', '618', '619', '620', '623', '626', '628', '629', '630', '631', '636', '641', '646', '650', '651', '657', '660', '661', '662', '667', '669', '678', '681', '682', '701', '702', '703', '704', '706', '707', '708', '712', '713', '714', '715', '716', '717', '718', '719', '720', '724', '725', '727', '731', '732', '734', '737', '740', '743', '747', '754', '757', '760', '762', '763', '765', '769', '770', '772', '773', '774', '775', '779', '781', '785', '786', '801', '802', '803', '804', '805', '806', '808', '810', '812', '813', '814', '815', '816', '817', '818', '828', '830', '831', '832', '843', '845', '847', '848', '850', '856', '857', '858', '859', '860', '862', '863', '864', '865', '870', '872', '878', '901', '903', '904', '906', '907', '908', '909', '910', '912', '913', '914', '915', '916', '917', '918', '919', '920', '925', '928', '929', '930', '931', '934', '936', '937', '938', '940', '941', '947', '949', '951', '952', '954', '956', '959', '970', '971', '972', '973', '975', '978', '979', '980', '984', '985', '989'
    }
    
    canada_area_codes = {
        '204', '226', '236', '249', '250', '289', '306', '343', '365', '403', '416', '418', '431', '437', '438', '450', '506', '514', '519', '548', '579', '581', '587', '604', '613', '639', '647', '705', '709', '778', '780', '782', '807', '819', '825', '867', '873', '902', '905'
    }
    
    # Extract area code from various formats
    area_code = None
    
    # Pattern 1: (XXX) XXX-XXXX
    match = re.match(r'^\((\d{3})\)\s*\d{3}-\d{4}$', clean_value)
    if match:
        area_code = match.group(1)
    
    # Pattern 2: XXX-XXX-XXXX
    if not area_code:
        match = re.match(r'^(\d{3})-\d{3}-\d{4}$', clean_value)
        if match:
            area_code = match.group(1)
    
    # Pattern 3: +1-XXX-XXX-XXXX
    if not area_code:
        match = re.match(r'^\+1-(\d{3})-\d{3}-\d{4}$', clean_value)
        if match:
            area_code = match.group(1)
    
    # Pattern 4: 1-XXX-XXX-XXXX
    if not area_code:
        match = re.match(r'^1-(\d{3})-\d{3}-\d{4}$', clean_value)
        if match:
            area_code = match.group(1)
    
    # Pattern 5: XXX.XXX.XXXX
    if not area_code:
        match = re.match(r'^(\d{3})\.\d{3}\.\d{4}$', clean_value)
        if match:
            area_code = match.group(1)
    
    # Pattern 6: (XXX)XXX-XXXX
    if not area_code:
        match = re.match(r'^\((\d{3})\)\d{3}-\d{4}$', clean_value)
        if match:
            area_code = match.group(1)
    
    # Classify based on area code
    if area_code:
        if area_code in us_area_codes:
            return "controlled"  # US
        elif area_code in canada_area_codes:
            return "non-controlled"  # Canada
        else:
            return "non-controlled"  # Unknown area code = foreign
    
    # Handle international numbers
    if clean_value.startswith('+') and not clean_value.startswith('+1'):
        return "non-controlled"  # Foreign
    
    if clean_value.startswith('+1'):
        return "controlled"  # Could be US or Canada, but default to US
    
    # Handle numbers starting with 1 (US/Canada)
    if clean_value.startswith('1-') or clean_value.startswith('1 '):
        return "controlled"  # Likely US
    
    # Handle numbers with extensions (x, ext, etc.)
    if 'x' in clean_value.lower() or 'ext' in clean_value.lower():
        # Extract the main number part
        main_number = re.split(r'[xX]|ext', clean_value)[0].strip()
        return classify_phone_number(main_number)
    
    # Default to controlled (US) for unclear cases
    return "controlled"


def classify_pii(value: str, entity_type: str, content: str = "") -> str:
    """
    Classify detected PII values as controlled or non-controlled based on regex patterns.
    
    Args:
        value: The detected PII value
        entity_type: The type of entity detected by Presidio
        content: Full content for context (used for URL classification)
        
    Returns:
        Classification result - "controlled", "non-controlled", or "skip"
    """
    # Clean the value for better matching
    clean_value = value.strip()
    
    # Skip very short values that are likely false positives
    if len(clean_value) < 2:
        return "skip"
    
    # Special phone number handling (highest priority)
    if entity_type == "PHONE_NUMBER":
        return classify_phone_number(clean_value)
    
    # Special email handling
    if entity_type == "EMAIL_ADDRESS":
        return classify_email(clean_value)
    
    # Special address handling
    if entity_type == "LOCATION":
        # Check if this is actually an IBAN code (common false positive)
        if clean_value.startswith(('GB', 'DE', 'FR', 'IT', 'ES', 'NL', 'BE', 'AT', 'PT', 'IE', 'FI', 'LU', 'MT', 'CY', 'EE', 'LV', 'LT', 'SI', 'SK', 'HR', 'BG', 'RO', 'PL', 'CZ', 'HU', 'SE', 'DK', 'NO', 'CH', 'LI', 'IS', 'MC', 'SM', 'VA', 'AD', 'AL', 'BA', 'MK', 'ME', 'RS', 'TR', 'XK')):
            # Check if it has the right length for an IBAN (typically 15-34 characters)
            if 15 <= len(clean_value) <= 34:
                return "non-controlled"  # IBAN codes are foreign
        
        # Check for foreign cities/locations
        foreign_cities = [
            'london', 'paris', 'berlin', 'madrid', 'rome', 'amsterdam', 'brussels', 'vienna',
            'prague', 'budapest', 'warsaw', 'stockholm', 'oslo', 'copenhagen', 'helsinki',
            'dublin', 'edinburgh', 'glasgow', 'manchester', 'birmingham', 'liverpool',
            'toronto', 'vancouver', 'montreal', 'calgary', 'edmonton', 'ottawa',
            'sydney', 'melbourne', 'brisbane', 'perth', 'adelaide', 'canberra',
            'tokyo', 'osaka', 'kyoto', 'yokohama', 'nagoya', 'sapporo',
            'beijing', 'shanghai', 'guangzhou', 'shenzhen', 'chengdu', 'hangzhou',
            'mumbai', 'delhi', 'bangalore', 'chennai', 'kolkata', 'hyderabad',
            'mexico city', 'guadalajara', 'monterrey', 'puebla', 'tijuana',
            'sao paulo', 'rio de janeiro', 'brasilia', 'salvador', 'fortaleza',
            'moscow', 'saint petersburg', 'novosibirsk', 'yekaterinburg', 'kazan'
        ]
        
        if clean_value.lower() in foreign_cities:
            return "non-controlled"  # Foreign cities are non-controlled
            
        return classify_address(clean_value)
    
    # Special ID handling (covers various ID types)
    if entity_type in ["US_SSN", "US_ITIN", "US_DRIVER_LICENSE", "US_PASSPORT", "CREDIT_CARD", "ID", "PERSONAL_ID"]:
        return classify_id(clean_value, entity_type)
    
    # Handle specific entity types that need special classification
    if entity_type == "UK_NHS":
        return "non-controlled"  # UK National Health Service numbers
    
    if entity_type == "IBAN_CODE":
        return "non-controlled"  # International Bank Account Numbers are foreign
    
    if entity_type == "US_BANK_NUMBER":
        return "controlled"  # US bank account numbers
    
    if entity_type == "MEDICAL_LICENSE":
        return "controlled"  # US medical license numbers
    
    if entity_type == "NRP":
        return "controlled"  # US National Provider Identifier
    
    if entity_type == "DATE_TIME":
        return "controlled"  # Date/time patterns are generally US format
    
    if entity_type == "LOCATION":
        return "controlled"  # Location entities are generally US-based
    
    # Smart URL handling
    if entity_type == "URL":
        return classify_url(clean_value)
    
    # Check regex patterns
    for label, pattern in REGEX_PATTERNS.items():
        if re.search(pattern, clean_value, re.IGNORECASE):
            if "controlled" in label:
                return "controlled"
            elif "noncontrolled" in label:
                return "non-controlled"
    
    # Special handling for specific entity types
    if entity_type == "US_SSN":
        return "controlled"
    elif entity_type == "US_ITIN":
        return "controlled"
    elif entity_type == "US_DRIVER_LICENSE":
        return "controlled"
    elif entity_type == "CREDIT_CARD":
        return "controlled"
    elif entity_type == "US_PASSPORT":
        return "controlled"
    elif entity_type == "UK_NHS":
        return "non-controlled"  # UK National Health Service numbers
    
    # Fallback classification based on entity type
    controlled_types = {"US_SSN", "US_DRIVER_LICENSE", "US_PASSPORT", "CREDIT_CARD", "US_ITIN", "US_ZIP"}
    noncontrolled_types = {"PERSON", "ORGANIZATION"}
    
    if entity_type in controlled_types:
        return "controlled"
    elif entity_type in noncontrolled_types:
        return "non-controlled"
    
    # Default to controlled (US) instead of non-controlled
    return "controlled"


def scan_file(file_path: str) -> List[Dict[str, Any]]:
    """
    Scan a file for PII using Microsoft Presidio and custom classification.
    
    Args:
        file_path: Path to the file to scan
        
    Returns:
        List of dictionaries containing PII findings
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            content = file.read()
    except Exception as e:
        print(f"[❌] Error reading file {file_path}: {e}")
        return []
    
    analyzer = get_analyzer()
    results = analyzer.analyze(text=content, language="en")
    
    findings = []
    for result in results:
        # Filter out false positives
        value = content[result.start:result.end]
        
        # Skip very short values that are likely false positives
        if len(value.strip()) < 2:
            continue
            
        # Skip obvious HTML tags and false positives for driver's license
        if result.entity_type == "US_DRIVER_LICENSE":
            clean_value = value.strip()
            # Only skip if it's clearly an HTML tag (starts with < or ends with >)
            if clean_value.startswith('<') or clean_value.endswith('>') or len(clean_value) < 3:
                continue
            
        # Skip partial email matches
        if result.entity_type == "URL" and '@' in value and '.' not in value:
            continue
            
        classification = classify_pii(value, result.entity_type, content)
        
        # Skip findings that should be filtered out
        if classification == "skip":
            continue
        
        findings.append({
            'file_path': file_path,
            'entity_type': result.entity_type,
            'value': value,
            'confidence': result.score,
            'classification': classification,
            'start': result.start,
            'end': result.end
        })
    
    return findings
