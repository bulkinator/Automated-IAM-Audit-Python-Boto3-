# AWS IAM Audit Test Results

## Test Overview

This document shows the results from the automated AWS IAM audit script. The audit was run against a sandbox AWS account and generated risk-ranked findings for IAM users, roles, policies, MFA configuration, and wildcard permissions.

| Item | Result |
|---|---|
| Project | Automated AWS IAM Audit Tool |
| Tooling | Python, Boto3, AWS IAM Credential Report, IAM Authorization Details API |
| AWS Account | `REDACTED_ACCOUNT_ID` |
| Test Date | 2026-07-02 |
| Script Run | `python IAM-audit.py` |
| Report Format | Terminal output, JSON, CSV |


## Audit Summary

| Severity | Count |
|---|---:|
| CRITICAL | 3 |
| HIGH | 2 |
| MEDIUM | 23 |
| LOW | 0 |
| **Total** | **28** |

## Key Results

The audit found several high-impact IAM security issues:

- The AWS root account did not have MFA enabled.
- The `admin` IAM user had console access without MFA.
- The `admin` IAM user had the AWS managed `AdministratorAccess` policy attached.
- An AWS SSO reserved role also had `AdministratorAccess` attached.
- Multiple managed policies contained wildcard actions or wildcard resources, which should be reviewed for least privilege.

## Critical and High Findings

| Severity | Resource Type | Resource Name | Issue | Evidence | Recommendation |
|---|---|---|---|---|---|
| CRITICAL | IAM User | `admin` | User has AWS managed AdministratorAccess policy attached | `arn:aws:iam::aws:policy/AdministratorAccess` | Remove AdministratorAccess and replace it with least-privilege permissions. |
| CRITICAL | Managed Policy | `AdministratorAccess` | Managed policy allows all actions on all resources | `arn:aws:iam::aws:policy/AdministratorAccess` | Replace broad admin permissions with least-privilege permissions. |
| CRITICAL | Root Account | `<root_account>` | Root account MFA is disabled | `mfa_active=false` | Enable MFA on the AWS root account immediately. |
| HIGH | IAM Role | `AWSReservedSSO_AWSAdministratorAccess_90f3d0f5ebf12122` | Role has AWS managed AdministratorAccess policy attached | `arn:aws:iam::aws:policy/AdministratorAccess` | Use least-privilege permissions instead of AdministratorAccess. |
| HIGH | IAM User | `admin` | Console password enabled but MFA is disabled | `password_enabled=true, mfa_active=false` | Enable MFA for this IAM user or remove console access if not required. |

## Medium Findings Summary

The medium findings mainly relate to wildcard permissions such as `Resource: "*"`, service-wide actions such as `s3:*`, or policies that use broad AWS-managed permissions. Some AWS-managed service policies use wildcards by design, so these should be reviewed rather than immediately treated as confirmed vulnerabilities.

| # | Resource Type | Resource Name | Issue | Evidence | Recommendation |
|---:|---|---|---|---|---|
| 1 | IAM Role Inline Policy | `AWSReservedSSO_AWSServiceCatalogEndUserAccess_c7d891931deb5deb/AwsSSOInlinePolicy` | Inline policy contains wildcard permissions | `Wildcard resource: *` | Review the role policy and reduce wildcard permissions where possible. |
| 2 | Managed Policy | `AWSCloudTrail_FullAccess` | Managed policy contains wildcard permissions | `Wildcard resource: *; Wildcard resource: *; Wildcard action: cloudtrail:*; Wildcard resource: *; Wildcard resource: *; Wildcard resource: *; Wildcard resource: *; Wildcard resource: *; Wildcard resource: *` | Review whether the wildcard permissions are required. |
| 3 | Managed Policy | `AWSConfigRoleForOrganizations` | Managed policy contains wildcard permissions | `Wildcard resource: *` | Review whether the wildcard permissions are required. |
| 4 | Managed Policy | `AWSControlTowerAdminPolicy` | Managed policy contains wildcard permissions | `Wildcard resource: *` | Review whether the wildcard permissions are required. |
| 5 | Managed Policy | `AWSControlTowerIdentityCenterManagementPolicy` | Managed policy contains wildcard permissions | `Wildcard resource: *; Wildcard resource: *` | Review whether the wildcard permissions are required. |
| 6 | Managed Policy | `AWSControlTowerServiceRolePolicy` | Managed policy contains wildcard permissions | `Wildcard resource: *; Wildcard resource: *; Wildcard resource: *; Wildcard resource: *; Wildcard resource: *; Wildcard resource: *; Wildcard resource: *; Wildcard resource: *` | Review whether the wildcard permissions are required. |
| 7 | Managed Policy | `AWSOrganizationsFullAccess` | Managed policy contains wildcard permissions | `Wildcard action: organizations:*; Wildcard resource: *; Wildcard resource: *; Wildcard resource: *` | Review whether the wildcard permissions are required. |
| 8 | Managed Policy | `AWSOrganizationsServiceTrustPolicy` | Managed policy contains wildcard permissions | `Wildcard resource: *` | Review whether the wildcard permissions are required. |
| 9 | Managed Policy | `AWSResourceExplorerServiceRolePolicy` | Managed policy contains wildcard permissions | `Wildcard resource: *; Wildcard resource: *; Wildcard resource: *` | Review whether the wildcard permissions are required. |
| 10 | Managed Policy | `AWSSSOServiceRolePolicy` | Managed policy contains wildcard permissions | `Wildcard resource: *; Wildcard resource: *; Wildcard resource: *; Wildcard resource: *; Wildcard resource: *` | Review whether the wildcard permissions are required. |
| 11 | Managed Policy | `AWSServiceCatalogAdminFullAccess` | Managed policy contains wildcard permissions | `Wildcard resource: *; Wildcard resource: *; Wildcard resource: *` | Review whether the wildcard permissions are required. |
| 12 | Managed Policy | `AWSServiceCatalogEndUserFullAccess` | Managed policy contains wildcard permissions | `Wildcard resource: *; Wildcard resource: *` | Review whether the wildcard permissions are required. |
| 13 | Managed Policy | `AWSSupportServiceRolePolicy` | Managed policy contains wildcard permissions | `Wildcard resource: *; Wildcard resource: *; Wildcard resource: *` | Review whether the wildcard permissions are required. |
| 14 | Managed Policy | `AWSTrustedAdvisorServiceRolePolicy` | Managed policy contains wildcard permissions | `Wildcard resource: *` | Review whether the wildcard permissions are required. |
| 15 | Managed Policy | `AdministratorAccess` | Managed policy contains wildcard permissions | `Wildcard action: *; Wildcard resource: *` | Review whether the wildcard permissions are required. |
| 16 | Managed Policy | `AmazonDocDBElasticFullAccess` | Managed policy contains wildcard permissions | `Wildcard resource: *; Wildcard resource: *; Wildcard resource: *; Wildcard resource: *; Wildcard resource: *; Wildcard resource: *` | Review whether the wildcard permissions are required. |
| 17 | Managed Policy | `AmazonS3FullAccess` | Managed policy contains wildcard permissions | `Wildcard action: s3:*; Wildcard action: s3-object-lambda:*; Wildcard resource: *` | Review whether the wildcard permissions are required. |
| 18 | Managed Policy | `AmazonSQSFullAccess` | Managed policy contains wildcard permissions | `Wildcard action: sqs:*; Wildcard resource: *` | Review whether the wildcard permissions are required. |
| 19 | Managed Policy | `CloudFormationStackSetsOrgAdminServiceRolePolicy` | Managed policy contains wildcard permissions | `Wildcard resource: *` | Review whether the wildcard permissions are required. |
| 20 | Managed Policy | `CloudTrailServiceRolePolicy` | Managed policy contains wildcard permissions | `Wildcard action: cloudtrail:*; Wildcard resource: *; Wildcard resource: *; Wildcard resource: *; Wildcard resource: *` | Review whether the wildcard permissions are required. |
| 21 | Managed Policy | `IAMUserChangePassword` | Managed policy contains wildcard permissions | `Wildcard resource: *` | Review whether the wildcard permissions are required. |
| 22 | Managed Policy | `PowerUserAccess` | Managed policy contains wildcard permissions | `Uses Allow with NotAction; Wildcard resource: *; Wildcard resource: *` | Review whether the wildcard permissions are required. |
| 23 | Managed Policy | `ViewOnlyAccess` | Managed policy contains wildcard permissions | `Wildcard resource: *` | Review whether the wildcard permissions are required. |

## Findings by Resource Type

| Resource Type | Count |
|---|---:|
| Managed Policy | 23 |
| IAM User | 2 |
| Root Account | 1 |
| IAM Role | 1 |
| IAM Role Inline Policy | 1 |

## Remediation Plan

| Priority | Action | Reason |
|---:|---|---|
| 1 | Enable MFA for the AWS root account. | Root account compromise can lead to full AWS account takeover. |
| 2 | Enable MFA for the `admin` IAM user or remove console login. | Reduces risk from stolen passwords. |
| 3 | Remove direct `AdministratorAccess` from the `admin` IAM user. | Replaces broad permissions with least privilege. |
| 4 | Review the AWS SSO AdministratorAccess role. | Ensure admin access is limited to approved users only. |
| 5 | Review wildcard permissions in managed and inline policies. | Wildcards may allow excessive access beyond business need. |
| 6 | Re-run the IAM audit after remediation. | Confirms that fixes reduced the number of findings. |

## Evidence Collected

The script successfully collected:

- IAM Credential Report
- IAM users and MFA status
- IAM access key metadata
- IAM roles and attached policies
- IAM role trust policies
- Managed and inline IAM policies
- JSON and CSV report outputs

## Conclusion

The automated IAM audit tool successfully identified risky IAM configurations in the sandbox AWS account. The most important issues were missing MFA on the root account and admin user, direct AdministratorAccess assignment, and broad wildcard permissions. This demonstrates the tool’s ability to automate IAM security checks, classify risk by severity, and produce actionable remediation guidance.

## Resume Project Summary

Built a Python and Boto3-based AWS IAM audit tool that detects missing MFA, stale or risky credentials, AdministratorAccess assignments, wildcard IAM permissions, and broad trust policies. The tool generates severity-ranked findings and exports results to JSON and CSV for security review and remediation tracking.