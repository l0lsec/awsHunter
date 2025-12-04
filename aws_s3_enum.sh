#!/bin/bash
# Faster version - skip log buckets, limit 100 files per bucket

# Colors
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
NC='\033[0m'

OUTPUT_FILE="/path/to/save/s3_quick_enum.txt"

# Banner
echo -e "${CYAN}"
cat << 'EOF'
    ┌─────────────────────────────────────────────────────────────┐
    │                                                             │
    │     ███████╗██████╗     ███████╗███╗   ██╗██╗   ██╗███╗   ███╗   │
    │     ██╔════╝╚════██╗    ██╔════╝████╗  ██║██║   ██║████╗ ████║   │
    │     ███████╗ █████╔╝    █████╗  ██╔██╗ ██║██║   ██║██╔████╔██║   │
    │     ╚════██║ ╚═══██╗    ██╔══╝  ██║╚██╗██║██║   ██║██║╚██╔╝██║   │
    │     ███████║██████╔╝    ███████╗██║ ╚████║╚██████╔╝██║ ╚═╝ ██║   │
    │     ╚══════╝╚═════╝     ╚══════╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝     ╚═╝   │
    │                                                             │
    └─────────────────────────────────────────────────────────────┘
EOF
echo -e "${YELLOW}"
cat << 'EOF'
                    ╔═══════════════════════════════════╗
                    ║   🪣 S3 Bucket Quick Enumerator   ║
                    ║   📦 Recursive File Listing       ║
                    ╚═══════════════════════════════════╝
                         
              ⠀⠀⠀⠀⢀⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⡀
              ⠀⠀⠀⠀⣿⠀  🔓 BUCKET ACCESS  ⠀⣿
              ⠀⠀⠀⠀⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿
              ⠀⠀⠀⠀⣿⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣿
              ⠀⠀⠀⠀⠈⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠈
EOF
echo -e "${NC}"

echo "S3 Quick Enumeration - $(date)" > "$OUTPUT_FILE"
echo -e "${GREEN}[+] Starting S3 enumeration...${NC}"

for bucket in $(awk '{print $3}' /path/to/s3_buckets.txt); do
    # Skip known log/audit buckets
    case "$bucket" in
        *cloudtrail*|*awslog*|*macie*|*flowlog*|*access-log*|*AWSLogs*) 
            echo "Skipping log bucket: $bucket"
            continue 
            ;;
    esac
    
    echo "Processing: $bucket"
    {
        echo ""
        echo "=========================================="
        echo "BUCKET: $bucket"
        echo "=========================================="
        aws s3 ls "s3://$bucket" --recursive 2>&1 | head -100
    } >> "$OUTPUT_FILE"
done

echo -e "${GREEN}"
cat << 'EOF'
    ╔═══════════════════════════════════════════════════════════╗
    ║  ✅ S3 ENUMERATION COMPLETE                               ║
    ╚═══════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"
echo -e "${GREEN}[✓] Done! Results saved to: $OUTPUT_FILE${NC}"