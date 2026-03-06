# AWS Security Testing Script

```
╔═══════════════════════════════════════════════════════════════════╗
║           AWS Security Testing Script                             ║
║           Multi-Region Credential & Service Enumeration           ║
╚═══════════════════════════════════════════════════════════════════╝
```

A comprehensive bash script for testing AWS security misconfigurations, credential enumeration, and service access analysis.

## Author

**Sedric Louissaint**  
🐦 Twitter: [@l0lsec](https://twitter.com/l0lsec)  
💻 GitHub: l0lsec

---

## Overview

This tool automates the process of testing AWS environments for common security misconfigurations, including:

- 🔓 **Cognito Identity Pool** unauthenticated access testing
- 🔑 **Credential enumeration** from leaked/exposed keys
- 🔍 **Service access enumeration** across 60+ AWS services
- 🌍 **Multi-region testing** for comprehensive coverage
- 🕵️ **Privilege escalation** path detection
- 🔐 **Secrets extraction** from Lambda, SSM, Secrets Manager, and more

---

## Features

### Service Coverage

The script tests access to **60+ AWS services** organized into categories:

| Category | Services |
|----------|----------|
| **Global** | S3, IAM Users/Roles, Route53, CloudFront, Organizations |
| **Compute** | Lambda, EC2, ECS, EKS, Elastic Beanstalk, Lightsail, Batch, EMR, SageMaker |
| **Database** | DynamoDB, RDS, ElastiCache, Redshift, DocumentDB, Neptune |
| **Storage** | EFS, FSx, AWS Backup |
| **Secrets** | Secrets Manager, SSM Parameter Store, KMS |
| **Messaging** | SQS, SNS, Kinesis, Firehose, EventBridge, MQ |
| **Serverless** | API Gateway, AppSync, Amplify, Step Functions |
| **Security** | GuardDuty, SecurityHub, Inspector, Macie, Config, CloudTrail, WAFv2 |
| **Network** | VPC, Security Groups, Subnets, NAT/Internet Gateways, ELB, VPN |
| **DevTools** | CodeCommit, CodeBuild, CodePipeline |
| **And more...** | ECR, Glue, Athena, IoT, SES, ACM, OpenSearch |

### Key Capabilities

- ✅ **Selective Service Testing** - Test individual services or categories
- ✅ **Multi-Region Support** - Test across all AWS regions
- ✅ **Automatic Secret Detection** - Find exposed credentials in Lambda env vars, SSM, CloudFormation
- ✅ **Privilege Escalation Analysis** - Identify dangerous IAM permissions
- ✅ **Comprehensive Reporting** - Markdown reports with findings summary
- ✅ **Multiple Credential Sources** - Direct keys, Cognito pools, encoded strings

---

## Installation

### Prerequisites

- **Bash 4.0+** (macOS users may need to upgrade via Homebrew)
- **AWS CLI v2** - [Installation Guide](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html)
- **jq** - JSON processor (`brew install jq` or `apt install jq`)

### Setup

```bash
# Clone or download the script
git clone <repository-url>
cd aws

# Make executable
chmod +x awsHunter.sh
```

---

## Usage

### Basic Usage

```bash
# Using environment variables
export AWS_ACCESS_KEY_ID="AKIAXXXXXXXXXX"
export AWS_SECRET_ACCESS_KEY="your-secret-key"
./awsHunter.sh

# Using command-line arguments
./awsHunter.sh -a AKIAXXXXXXXXXX -s your-secret-key -r us-east-1
```

### Command-Line Options

```
Options:
    -h, --help              Show help message
    -r, --region REGION     AWS region (default: us-east-1)
    -p, --pool-id ID        Cognito Identity Pool ID to test
    -e, --encoded CREDS     Base64 encoded credentials string to decode
    -a, --access-key KEY    AWS Access Key ID
    -s, --secret-key KEY    AWS Secret Access Key
    -t, --session-token TOK AWS Session Token (for temporary credentials)
    -o, --output DIR        Output directory
    -q, --quick             Quick mode - skip slower tests
    -v, --verbose           Verbose output
    -m, --multi-region      Test all AWS regions

Service Selection:
    --service SERVICES      Comma-separated list of services to test
    --service-category CAT  Test all services in specified categories
    --list-services         Show all available services and categories

Additional:
    --regions REGIONS       Comma-separated list of specific regions
    --skip-cognito          Skip Cognito Identity Pool testing
    --skip-privesc          Skip privilege escalation checks
    --skip-secrets          Skip secret extraction
    --test-create           Enable destructive tests (CAUTION!)
```

---

## Examples

### Test Specific Services

```bash
# Test only S3 and Lambda
./awsHunter.sh --service s3,lambda

# Test only database services
./awsHunter.sh --service-category database

# Test multiple categories
./awsHunter.sh --service-category database,secrets,compute
```

### List Available Services

```bash
./awsHunter.sh --list-services
```

### Test Cognito Identity Pool

```bash
./awsHunter.sh -p us-east-1:xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
```

### Multi-Region Testing

```bash
# Test all regions
./awsHunter.sh -m

# Test specific regions
./awsHunter.sh --regions us-east-1,us-west-2,eu-west-1
```

### Quick Security Scan

```bash
./awsHunter.sh --quick --skip-privesc
```

### Decode Leaked Credentials

```bash
./awsHunter.sh -e "base64-encoded-credentials-string"
```

---

## Service Categories

Use `--service-category` with any of these category names:

| Category | Description |
|----------|-------------|
| `global` | Global services (S3, IAM, Route53, CloudFront, Organizations) |
| `compute` | Compute services (Lambda, EC2, ECS, EKS, etc.) |
| `database` | Database services (DynamoDB, RDS, ElastiCache, etc.) |
| `storage` | Storage services (EFS, FSx, Backup) |
| `secrets` | Secret management (Secrets Manager, SSM, KMS) |
| `messaging` | Messaging services (SQS, SNS, Kinesis, etc.) |
| `containers` | Container services (ECR) |
| `serverless` | Serverless (API Gateway, AppSync, Amplify, Step Functions) |
| `data` | Data services (Glue, Athena) |
| `devtools` | Developer tools (CodeCommit, CodeBuild, CodePipeline) |
| `iot` | IoT services (IoT, Transfer) |
| `security` | Security services (GuardDuty, SecurityHub, Inspector, etc.) |
| `network` | Network services (VPC, Security Groups, ELB, etc.) |
| `email` | Email services (SES) |
| `logs` | Logging (CloudWatch Logs) |
| `other` | Other services (Cognito, CloudFormation, ACM, etc.) |

---

## Output

Results are saved to `./awsHunter_results_TIMESTAMP/`:

| File | Description |
|------|-------------|
| `security_report.md` | Full security assessment report |
| `ALL_SECRETS_FOUND.txt` | Consolidated list of discovered secrets |
| `caller_identity.json` | AWS identity information |
| `*.json` | Raw API responses for each service |
| `*_secrets.txt` | Extracted secrets per service |
| `open_security_groups.txt` | Security groups with 0.0.0.0/0 access |
| `s3_public_buckets.txt` | Buckets with public access |

---

## Sample Output

```
╔═══════════════════════════════════════════════════════════════════╗
║           AWS Security Testing Script                             ║
║           Multi-Region Credential & Service Enumeration           ║
╚═══════════════════════════════════════════════════════════════════╝

[i] Testing only selected services: s3 lambda dynamodb

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  TESTING GLOBAL SERVICES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Testing S3 (List Buckets)... [✓] ACCESS GRANTED - Results saved to s3_buckets.txt
[🚨 FINDING] Can list 47 S3 buckets!

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  QUICK SUMMARY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  S3 Buckets:        47
  DynamoDB Tables:   12
  Lambda Functions:  23
  SECRETS FOUND:     8
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

---

## Security Considerations

⚠️ **Important**: This tool is intended for authorized security testing only.

- Always obtain proper authorization before testing
- Use on accounts you own or have explicit permission to test
- The `--test-create` flag will create resources - use with extreme caution
- Credentials used may be logged in CloudTrail
- Review findings responsibly and report to appropriate parties

---

## Environment Variables

| Variable | Description |
|----------|-------------|
| `AWS_ACCESS_KEY_ID` | AWS Access Key ID |
| `AWS_SECRET_ACCESS_KEY` | AWS Secret Access Key |
| `AWS_SESSION_TOKEN` | AWS Session Token (optional) |
| `AWS_REGION` | AWS Region |
| `COGNITO_IDENTITY_POOL_ID` | Cognito Identity Pool ID |
| `ENCODED_CREDENTIALS` | Encoded credentials to decode |

---

## Troubleshooting

### "Access Denied" on All Services

- Verify credentials are valid: `aws sts get-caller-identity`
- Check if credentials have expired (ASIA prefix = temporary)
- Ensure the IAM policy allows the tested actions

### Script Errors

- Ensure you're using Bash 4.0+: `bash --version`
- Verify jq is installed: `jq --version`
- Check AWS CLI version: `aws --version`

### Slow Performance

- Use `--quick` mode for faster scans
- Limit regions with `--regions`
- Test specific services with `--service`

---

## Contributing

Contributions are welcome! Please submit issues and pull requests.

---

## License

This tool is provided for educational and authorized security testing purposes only. Use responsibly.

---

## Acknowledgments

Created by **Sedric Louissaint** ([@l0lsec](https://twitter.com/sedric____) | ShowUpShowOut)

*"Security is not a product, but a process."*

