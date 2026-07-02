import boto3
import botocore
import csv
import io
import json
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import unquote


REPORT_DIR = Path("reports")
REPORT_DIR.mkdir(exist_ok=True)

MAX_KEY_AGE_DAYS = 90
MAX_INACTIVE_DAYS = 90


def utc_now():
    return datetime.now(timezone.utc)


def parse_aws_date(value):
    if not value or value in ["N/A", "no_information", "not_supported"]:
        return None

    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except Exception:
        return None


def age_in_days(date_value):
    if not date_value:
        return None
    return (utc_now() - date_value).days


def add_finding(findings, severity, resource_type, resource_name, issue, evidence, recommendation):
    findings.append({
        "severity": severity,
        "resource_type": resource_type,
        "resource_name": resource_name,
        "issue": issue,
        "evidence": evidence,
        "recommendation": recommendation
    })


def get_account_id(session):
    sts = session.client("sts")
    return sts.get_caller_identity()["Account"]


def generate_and_get_credential_report(iam):
    print("[+] Generating IAM credential report...")

    iam.generate_credential_report()

    for _ in range(12):
        try:
            response = iam.get_credential_report()
            content = response["Content"].decode("utf-8")
            return list(csv.DictReader(io.StringIO(content)))
        except iam.exceptions.ReportInProgressException:
            time.sleep(5)
        except iam.exceptions.ReportNotPresentException:
            time.sleep(5)

    raise RuntimeError("Credential report was not ready. Try running the script again.")


def audit_credential_report(rows, findings):
    print("[+] Auditing credential report...")

    for row in rows:
        username = row["user"]

        # Root account checks
        if username == "<root_account>":
            if row.get("mfa_active") == "false":
                add_finding(
                    findings,
                    "CRITICAL",
                    "Root Account",
                    username,
                    "Root account MFA is disabled",
                    "mfa_active=false",
                    "Enable MFA on the AWS root account immediately."
                )
            continue

        # IAM user MFA check
        if row.get("password_enabled") == "true" and row.get("mfa_active") == "false":
            add_finding(
                findings,
                "HIGH",
                "IAM User",
                username,
                "Console password enabled but MFA is disabled",
                "password_enabled=true, mfa_active=false",
                "Enable MFA for this IAM user or remove console access if not required."
            )

        # Inactive user check
        password_last_used = parse_aws_date(row.get("password_last_used"))
        user_created = parse_aws_date(row.get("user_creation_time"))

        if row.get("password_enabled") == "true":
            if password_last_used:
                inactive_days = age_in_days(password_last_used)
                if inactive_days and inactive_days > MAX_INACTIVE_DAYS:
                    add_finding(
                        findings,
                        "MEDIUM",
                        "IAM User",
                        username,
                        "IAM console user has not logged in recently",
                        f"password_last_used={row.get('password_last_used')}",
                        "Disable or remove unused IAM users after confirming they are no longer needed."
                    )
            elif user_created and age_in_days(user_created) > MAX_INACTIVE_DAYS:
                add_finding(
                    findings,
                    "MEDIUM",
                    "IAM User",
                    username,
                    "IAM console user appears unused",
                    f"user_creation_time={row.get('user_creation_time')}, password_last_used=N/A",
                    "Review whether this IAM user is still required."
                )

        # Access key checks
        for key_number in ["1", "2"]:
            key_active = row.get(f"access_key_{key_number}_active")
            key_rotated = parse_aws_date(row.get(f"access_key_{key_number}_last_rotated"))
            key_last_used = parse_aws_date(row.get(f"access_key_{key_number}_last_used_date"))

            if key_active == "true":
                key_age = age_in_days(key_rotated)

                if key_age and key_age > MAX_KEY_AGE_DAYS:
                    add_finding(
                        findings,
                        "HIGH",
                        "Access Key",
                        f"{username} access_key_{key_number}",
                        "Active access key is older than rotation threshold",
                        f"last_rotated={row.get(f'access_key_{key_number}_last_rotated')}",
                        "Rotate the access key and remove the old key after validation."
                    )

                if key_last_used:
                    unused_days = age_in_days(key_last_used)
                    if unused_days and unused_days > MAX_INACTIVE_DAYS:
                        add_finding(
                            findings,
                            "MEDIUM",
                            "Access Key",
                            f"{username} access_key_{key_number}",
                            "Active access key has not been used recently",
                            f"last_used={row.get(f'access_key_{key_number}_last_used_date')}",
                            "Disable the key first, monitor for breakage, then delete it."
                        )
                else:
                    add_finding(
                        findings,
                        "MEDIUM",
                        "Access Key",
                        f"{username} access_key_{key_number}",
                        "Active access key has no recorded usage",
                        "last_used=N/A",
                        "Confirm whether the key is needed. Disable and delete it if unused."
                    )


def ensure_list(value):
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def decode_policy_document(document):
    if isinstance(document, dict):
        return document

    if isinstance(document, str):
        try:
            decoded = unquote(document)
            return json.loads(decoded)
        except Exception:
            return {}

    return {}


def is_admin_like_policy(policy_doc):
    policy_doc = decode_policy_document(policy_doc)
    statements = ensure_list(policy_doc.get("Statement"))

    for statement in statements:
        if statement.get("Effect") != "Allow":
            continue

        actions = ensure_list(statement.get("Action"))
        resources = ensure_list(statement.get("Resource"))

        has_all_actions = "*" in actions
        has_all_resources = "*" in resources

        if has_all_actions and has_all_resources:
            return True

    return False


def has_wildcard_risk(policy_doc):
    policy_doc = decode_policy_document(policy_doc)
    statements = ensure_list(policy_doc.get("Statement"))

    risky = []

    for statement in statements:
        if statement.get("Effect") != "Allow":
            continue

        actions = ensure_list(statement.get("Action"))
        resources = ensure_list(statement.get("Resource"))

        if statement.get("NotAction"):
            risky.append("Uses Allow with NotAction")

        for action in actions:
            if action == "*" or str(action).endswith(":*"):
                risky.append(f"Wildcard action: {action}")

        for resource in resources:
            if resource == "*":
                risky.append("Wildcard resource: *")

    return risky


def trust_policy_is_broad(policy_doc):
    policy_doc = decode_policy_document(policy_doc)
    statements = ensure_list(policy_doc.get("Statement"))

    for statement in statements:
        if statement.get("Effect") != "Allow":
            continue

        principal = statement.get("Principal")

        if principal == "*":
            return True

        if isinstance(principal, dict):
            aws_principal = principal.get("AWS")
            principals = ensure_list(aws_principal)

            for p in principals:
                if p == "*":
                    return True

    return False


def audit_authorization_details(iam, findings):
    print("[+] Auditing IAM authorization details...")

    paginator = iam.get_paginator("get_account_authorization_details")

    pages = paginator.paginate(
        Filter=[
            "User",
            "Group",
            "Role",
            "LocalManagedPolicy",
            "AWSManagedPolicy"
        ]
    )

    for page in pages:
        # Users
        for user in page.get("UserDetailList", []):
            username = user["UserName"]

            for policy in user.get("AttachedManagedPolicies", []):
                if policy["PolicyName"] == "AdministratorAccess":
                    add_finding(
                        findings,
                        "CRITICAL",
                        "IAM User",
                        username,
                        "User has AWS managed AdministratorAccess policy attached",
                        policy["PolicyArn"],
                        "Remove AdministratorAccess and replace it with least-privilege permissions."
                    )

            for inline_policy in user.get("UserPolicyList", []):
                policy_name = inline_policy["PolicyName"]
                policy_doc = inline_policy["PolicyDocument"]

                if is_admin_like_policy(policy_doc):
                    add_finding(
                        findings,
                        "CRITICAL",
                        "IAM User Inline Policy",
                        f"{username}/{policy_name}",
                        "Inline policy allows all actions on all resources",
                        "Action=* and Resource=*",
                        "Replace with specific actions and resources."
                    )

                risks = has_wildcard_risk(policy_doc)
                if risks:
                    add_finding(
                        findings,
                        "MEDIUM",
                        "IAM User Inline Policy",
                        f"{username}/{policy_name}",
                        "Inline policy contains wildcard permissions",
                        "; ".join(risks),
                        "Review the policy and reduce wildcard permissions where possible."
                    )

        # Groups
        for group in page.get("GroupDetailList", []):
            group_name = group["GroupName"]

            for policy in group.get("AttachedManagedPolicies", []):
                if policy["PolicyName"] == "AdministratorAccess":
                    add_finding(
                        findings,
                        "HIGH",
                        "IAM Group",
                        group_name,
                        "Group has AWS managed AdministratorAccess policy attached",
                        policy["PolicyArn"],
                        "Avoid broad admin groups. Use role-based least privilege instead."
                    )

            for inline_policy in group.get("GroupPolicyList", []):
                policy_name = inline_policy["PolicyName"]
                policy_doc = inline_policy["PolicyDocument"]

                if is_admin_like_policy(policy_doc):
                    add_finding(
                        findings,
                        "CRITICAL",
                        "IAM Group Inline Policy",
                        f"{group_name}/{policy_name}",
                        "Inline policy allows all actions on all resources",
                        "Action=* and Resource=*",
                        "Replace with specific actions and resources."
                    )

        # Roles
        for role in page.get("RoleDetailList", []):
            role_name = role["RoleName"]

            trust_doc = role.get("AssumeRolePolicyDocument")
            if trust_doc and trust_policy_is_broad(trust_doc):
                add_finding(
                    findings,
                    "HIGH",
                    "IAM Role Trust Policy",
                    role_name,
                    "Role trust policy allows broad principal access",
                    "Principal=*",
                    "Restrict the trust policy to specific AWS accounts, users, roles, or services."
                )

            for policy in role.get("AttachedManagedPolicies", []):
                if policy["PolicyName"] == "AdministratorAccess":
                    add_finding(
                        findings,
                        "HIGH",
                        "IAM Role",
                        role_name,
                        "Role has AWS managed AdministratorAccess policy attached",
                        policy["PolicyArn"],
                        "Use least-privilege permissions instead of AdministratorAccess."
                    )

            for inline_policy in role.get("RolePolicyList", []):
                policy_name = inline_policy["PolicyName"]
                policy_doc = inline_policy["PolicyDocument"]

                if is_admin_like_policy(policy_doc):
                    add_finding(
                        findings,
                        "CRITICAL",
                        "IAM Role Inline Policy",
                        f"{role_name}/{policy_name}",
                        "Inline policy allows all actions on all resources",
                        "Action=* and Resource=*",
                        "Replace with specific actions and resources."
                    )

                risks = has_wildcard_risk(policy_doc)
                if risks:
                    add_finding(
                        findings,
                        "MEDIUM",
                        "IAM Role Inline Policy",
                        f"{role_name}/{policy_name}",
                        "Inline policy contains wildcard permissions",
                        "; ".join(risks),
                        "Review the role policy and reduce wildcard permissions where possible."
                    )

        # Customer/AWS managed policies
        for policy in page.get("Policies", []):
            policy_name = policy["PolicyName"]
            policy_arn = policy["Arn"]

            default_version = None
            for version in policy.get("PolicyVersionList", []):
                if version.get("IsDefaultVersion"):
                    default_version = version
                    break

            if not default_version:
                continue

            policy_doc = default_version.get("Document", {})

            if is_admin_like_policy(policy_doc):
                add_finding(
                    findings,
                    "CRITICAL",
                    "Managed Policy",
                    policy_name,
                    "Managed policy allows all actions on all resources",
                    policy_arn,
                    "Replace broad admin permissions with least-privilege permissions."
                )

            risks = has_wildcard_risk(policy_doc)
            if risks:
                add_finding(
                    findings,
                    "MEDIUM",
                    "Managed Policy",
                    policy_name,
                    "Managed policy contains wildcard permissions",
                    "; ".join(risks),
                    "Review whether the wildcard permissions are required."
                )


def export_reports(account_id, findings):
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")

    json_path = REPORT_DIR / f"iam-audit-{account_id}-{timestamp}.json"
    csv_path = REPORT_DIR / f"iam-audit-{account_id}-{timestamp}.csv"

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(findings, f, indent=2)

    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        fieldnames = [
            "severity",
            "resource_type",
            "resource_name",
            "issue",
            "evidence",
            "recommendation"
        ]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(findings)

    print(f"[+] JSON report saved: {json_path}")
    print(f"[+] CSV report saved:  {csv_path}")


def print_summary(findings):
    counts = {}

    for finding in findings:
        severity = finding["severity"]
        counts[severity] = counts.get(severity, 0) + 1

    print("\n========== IAM AUDIT SUMMARY ==========")
    print(f"Total findings: {len(findings)}")

    for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        print(f"{severity}: {counts.get(severity, 0)}")

    print("======================================\n")

    for finding in findings[:20]:
        print(f"[{finding['severity']}] {finding['resource_type']} - {finding['resource_name']}")
        print(f"  Issue: {finding['issue']}")
        print(f"  Fix:   {finding['recommendation']}")
        print()


def main():
    session = boto3.Session(profile_name="admin")

    iam = session.client("iam")

    findings = []

    account_id = get_account_id(session)
    print(f"[+] Auditing AWS account: {account_id}")

    credential_rows = generate_and_get_credential_report(iam)
    audit_credential_report(credential_rows, findings)

    audit_authorization_details(iam, findings)

    print_summary(findings)
    export_reports(account_id, findings)


if __name__ == "__main__":
    try:
        main()
    except botocore.exceptions.ProfileNotFound:
        print("AWS profile 'iam-audit' was not found. Run: aws configure --profile iam-audit")
    except botocore.exceptions.ClientError as e:
        print(f"AWS error: {e}")
    except Exception as e:
        print(f"Error: {e}")