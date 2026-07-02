# Automated AWS IAM Audit Tool

A Python + Boto3 cloud security project that audits AWS Identity and Access Management (IAM) for common security risks such as missing MFA, stale access keys, excessive permissions, wildcard policies, and overly broad role trust relationships.

This project is designed as a beginner-friendly cloud security automation tool and can be used as a resume project for cybersecurity, cloud security, DevSecOps, or SOC analyst roles.

---

## Project Overview

The script connects to an AWS account using a configured AWS CLI profile, collects IAM security information, runs security checks, and exports the results into CSV and JSON reports.

The tool currently checks for:

- Root account MFA disabled
- IAM users with console access but no MFA
- Old access keys
- Unused access keys
- IAM users, groups, or roles with `AdministratorAccess`
- Inline policies with full admin permissions
- Managed policies with wildcard permissions
- IAM role trust policies that allow overly broad principals

---

## Architecture

```text
AWS Account
   |
   |  Boto3 API Calls
   v
Python IAM Audit Script
   |
   |-- IAM Credential Report
   |-- IAM Users
   |-- IAM Groups
   |-- IAM Roles
   |-- IAM Policies
   |
   v
Security Findings
   |
   |-- Terminal Summary
   |-- CSV Report
   |-- JSON Report
```

---

## Skills Demonstrated

This project demonstrates practical skills in:

- AWS IAM security
- Cloud security auditing
- Python automation
- Boto3 usage
- MFA and credential hygiene checks
- Least privilege analysis
- Security report generation
- Risk classification and remediation guidance

---

## Project Structure

```text
iam-audit-project/
|
|-- audit_iam.py
|-- requirements.txt
|-- iam-audit-readonly-policy.json
|-- reports/
|   |-- test-result.md
|   |-- .csv & .json report
|-- README.md
```

---

## Requirements

You need the following installed:

- Python 3.10 or newer
- AWS CLI
- Boto3
- An AWS sandbox account
- An IAM user or IAM role with read-only IAM audit permissions

Install Python dependencies:

```bash
python -m pip install -r requirements.txt
```

Or install Boto3 directly:

```bash
python -m pip install boto3
```

---

## AWS Permissions Required

Create a dedicated IAM user or role for this project. Do not use your root account.

Example read-only policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "IAMReadOnlyAudit",
      "Effect": "Allow",
      "Action": [
        "iam:GenerateCredentialReport",
        "iam:GetCredentialReport",
        "iam:GetAccountAuthorizationDetails",
        "iam:Get*",
        "iam:List*",
        "sts:GetCallerIdentity",
        "access-analyzer:ListAnalyzers",
        "access-analyzer:ListFindings"
      ],
      "Resource": "*"
    }
  ]
}
```

This policy gives the script read-only access to IAM information. The script does not modify, delete, disable, or remediate any AWS resources.

---

## AWS CLI Setup

Configure an AWS CLI profile for the audit account:

```bash
aws configure --profile iam-audit
```

Enter the following when prompted:

```text
AWS Access Key ID: <your-access-key>
AWS Secret Access Key: <your-secret-key>
Default region name: ap-southeast-2
Default output format: json
```

The script uses this profile by default:

```python
session = boto3.Session(profile_name="iam-audit")
```

If you want to use your default AWS profile instead, change it to:

```python
session = boto3.Session()
```

---

## How to Run

From the project folder, run:

```bash
python audit_iam.py
```

Example output:

```text
[+] Auditing AWS account: 123456789012
[+] Generating IAM credential report...
[+] Auditing credential report...
[+] Auditing IAM authorization details...

========== IAM AUDIT SUMMARY ==========
Total findings: 7
CRITICAL: 1
HIGH: 3
MEDIUM: 3
LOW: 0
======================================
```

---

## Output Reports

The script creates reports in the `reports/` folder.

Example:

```text
reports/iam-audit-123456789012-20260702-140000.json
reports/iam-audit-123456789012-20260702-140000.csv
```

The CSV report is useful for reviewing findings in Excel or Google Sheets.

The JSON report is useful for automation, dashboards, or future integrations.

---

## Example Finding

```json
{
  "severity": "HIGH",
  "resource_type": "IAM User",
  "resource_name": "test-user",
  "issue": "Console password enabled but MFA is disabled",
  "evidence": "password_enabled=true, mfa_active=false",
  "recommendation": "Enable MFA for this IAM user or remove console access if not required."
}
```

---

## Security Checks Explained

### Root Account MFA Check

The root account has full control over the AWS account. If MFA is disabled, this is reported as a critical risk.

### IAM User MFA Check

IAM users with console access should use MFA. If a user can log in with only a password, the account is more vulnerable to credential theft.

### Access Key Age Check

Old access keys increase the risk of long-term credential exposure. The script flags access keys older than 90 days.

### Unused Access Key Check

Access keys that have not been used recently may be unnecessary. The script flags inactive keys so they can be reviewed and removed safely.

### AdministratorAccess Check

The script detects users, groups, or roles with the AWS managed `AdministratorAccess` policy. This is flagged because it violates least privilege unless there is a strong business need.

### Wildcard Policy Check

The script checks policies for broad permissions such as:

```json
"Action": "*"
```

or:

```json
"Resource": "*"
```

These permissions may allow more access than required.

### Role Trust Policy Check

The script checks IAM role trust policies for overly broad principals such as:

```json
"Principal": "*"
```

This can allow unintended users, services, or accounts to assume a role.

---

## Future Improvements

Planned improvements:

- Add HTML report output
- Add Slack or email alerts for critical findings
- Store reports in an S3 bucket
- Compare current findings with previous audit results
- Add AWS IAM Access Analyzer integration
- Add CloudTrail lookup for IAM user activity
- Deploy as an AWS Lambda function
- Schedule automatic scans with Amazon EventBridge
- Add unit tests
- Add GitHub Actions automation

---

## Optional Automation Architecture

```text
Amazon EventBridge Schedule
        |
        v
AWS Lambda Function
        |
        v
IAM Audit Script
        |
        v
S3 Report Bucket
        |
        v
SNS Email Alert
```

This allows the audit to run automatically every day or every week.


