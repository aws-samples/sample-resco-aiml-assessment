"""
Schema module for FinServ security findings.
Mirrors the schema used in bedrock_assessments/schema.py.
"""

from enum import Enum
from typing import Dict, Any
from pydantic import BaseModel, Field, validator
import re


class SeverityEnum(str, Enum):
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFORMATIONAL = "Informational"


class StatusEnum(str, Enum):
    FAILED = "Failed"
    PASSED = "Passed"
    NA = "N/A"


class Finding(BaseModel):
    """Represents a security finding with required fields and validations."""

    Check_ID: str = Field(
        ...,
        min_length=1,
        description="Unique check identifier (e.g., FS-01)",
    )
    Finding: str = Field(..., min_length=1, description="The name/title of the finding")
    Finding_Details: str = Field(
        ..., min_length=1, description="Detailed description of the finding"
    )
    Resolution: str = Field(
        ..., min_length=0, description="Steps to resolve the finding"
    )
    Reference: str = Field(..., description="Documentation reference URL")
    Severity: SeverityEnum = Field(..., description="Severity level of the finding")
    Status: StatusEnum = Field(..., description="Current status of the finding")

    @validator("Check_ID")
    def validate_check_id(cls, v):
        # Allow FS-NN pattern for FinServ checks
        pattern = r"^[A-Z]{2,3}-\d{2}$"
        if not re.match(pattern, v):
            raise ValueError(
                "Check_ID must follow pattern XX-NN (e.g., FS-01, BR-14, AC-05)"
            )
        return v

    @validator("Reference")
    def validate_reference_url(cls, v):
        if not str(v).startswith("https://"):
            raise ValueError("Reference URL must start with https://")
        return v


def create_finding(
    check_id: str,
    finding_name: str,
    finding_details: str,
    resolution: str,
    reference: str,
    severity: SeverityEnum,
    status: StatusEnum,
) -> Dict[str, Any]:
    """Create a validated finding dict."""
    finding = Finding(
        Check_ID=check_id,
        Finding=finding_name,
        Finding_Details=finding_details,
        Resolution=resolution,
        Reference=reference,
        Severity=severity,
        Status=status,
    )
    return dict(finding.model_dump())
