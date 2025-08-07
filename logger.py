# logger.py
"""
Logging module for PII scan results.
"""

import json
from typing import Dict, Any, List
from collections import defaultdict


class PIILogger:
    """Handles logging of PII scan results to JSONL file and console output."""
    
    def __init__(self, log_file: str = "scan_results.jsonl"):
        """
        Initialize the logger.
        
        Args:
            log_file: Path to the JSONL log file
        """
        self.log_file = log_file
    
    def log_finding(self, file_path: str, entity_type: str, value: str, 
                   confidence: float, classification: str) -> None:
        """
        Log a single PII finding to JSONL file.
        
        Args:
            file_path: Path to the scanned file
            entity_type: Type of PII detected
            value: The detected PII value
            confidence: Confidence score from the detector
            classification: Classification result (controlled/non-controlled/unknown)
        """
        log_entry = {
            "file": file_path,
            "entity_type": entity_type,
            "value": value,
            "confidence": confidence,
            "classification": classification
        }
        
        with open(self.log_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(log_entry) + "\n")
    
    def log_findings(self, findings: List[Dict[str, Any]]) -> None:
        """
        Log multiple findings to JSONL file.
        
        Args:
            findings: List of findings to log
        """
        for finding in findings:
            self.log_finding(
                finding["file_path"],
                finding["entity_type"],
                finding["value"],
                finding["confidence"],
                finding["classification"]
            )
    
    def print_summary(self, file_path: str, findings: List[Dict[str, Any]]) -> None:
        """
        Print a clean summary of findings to the console.
        
        Args:
            file_path: Path to the scanned file
            findings: List of findings for the file
        """
        if not findings:
            print(f"[ℹ️] No PII findings in {file_path}")
            return
        
        # Group findings by classification
        by_classification = defaultdict(list)
        for finding in findings:
            by_classification[finding["classification"]].append(finding)
        
        # Print summary
        print(f"\n📊 Scan Summary for: {file_path}")
        print(f"   Total findings: {len(findings)}")
        
        for classification, items in by_classification.items():
            print(f"   {classification.capitalize()}: {len(items)}")
        
        # Print detailed findings
        print("\n🔍 Detailed Findings:")
        for finding in findings:
            confidence_str = f"{finding['confidence']:.2f}"
            print(f"   [{finding['entity_type']}] {finding['value']} | Confidence: {confidence_str} | Classified: {finding['classification']}")
        
        print()  # Empty line for readability 