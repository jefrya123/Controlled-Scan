# regex_patterns.py

REGEX_PATTERNS = {
    # US ZIP codes (5-digit or ZIP+4 format) - CONTROLLED
    "controlled_zip": r"\b\d{5}(-\d{4})?\b",
    
    # US Social Security Numbers - CONTROLLED
    "controlled_ssn": r"\b\d{3}-\d{2}-\d{4}\b",
    
    # US phone numbers - CONTROLLED
    # Matches: (555) 123-4567, 555-123-4567, +1-555-123-4567
    "controlled_phone_us": r"\b(?:\(\d{3}\)\s*\d{3}-\d{4}|\d{3}-\d{3}-\d{4}|\+1-\d{3}-\d{3}-\d{4})\b",
    
    # US driver's license patterns - CONTROLLED
    "controlled_dl_us": r"\b[A-Z]{2}\d{6,7}\b",
    
    # US ITIN (Individual Taxpayer Identification Number) - CONTROLLED
    "controlled_itin_us": r"\b9\d{2}-\d{2}-\d{4}\b",
    
    # Foreign postcodes (UK, Canada, etc.) - NON-CONTROLLED
    "noncontrolled_postcode_uk": r"\b[A-Z]{1,2}\d[A-Z\d]?\s*\d[A-Z]{2}\b",
    "noncontrolled_postcode_ca": r"\b[A-Z]\d[A-Z]\s*\d[A-Z]\d\b",
    
    # Foreign National Insurance Numbers (UK) - NON-CONTROLLED
    "noncontrolled_nin_uk": r"\b[A-CEGHJ-NPR-TW-Z]{2}\d{6}[A-D]\b",
    
    # Foreign passport patterns - NON-CONTROLLED
    "noncontrolled_passport_uk": r"\b\d{9}\b",
    "noncontrolled_passport_ca": r"\b[A-Z]{2}\d{6}\b",
    
    # Email addresses (basic pattern) - NON-CONTROLLED
    "noncontrolled_email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"
}
