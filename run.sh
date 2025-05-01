#!/bin/bash
# run.sh - Bad Vibe Scanner Workflow Automation
# Description: Runs code quality checks and imports tasks into the database

set -e  # Exit on any error

# Terminal colors for better readability
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${BLUE}┌───────────────────────────────────────┐${NC}"
echo -e "${BLUE}│  Bad Vibe Scanner   :0)               │${NC}"
echo -e "${BLUE}└───────────────────────────────────────┘${NC}"

# Define parameters
TARGET_DIR="src/"
OUTPUT_FILE="test_results.md"
STRUCTURED_FILE="task_list.md"
DB_FILE="tasks.db"

# Step 1: Reset database
echo -e "\n${YELLOW}Step 1: Backup / Reset database${NC}"
if [ -f "${DB_FILE}" ]; then
    # Backup the database
    cp "${DB_FILE}" "${DB_FILE}.backup-$(date +%Y%m%d-%H%M%S)"
    # Check if the database has the necessary tables before trying to delete from them
    TABLES=$(sqlite3 "${DB_FILE}" ".tables" 2>/dev/null || echo "")
    if [[ "$TABLES" == *"tasks"* ]]; then
        sqlite3 "${DB_FILE}" "DELETE FROM tasks; DELETE FROM events; VACUUM;" 2>/dev/null || true
        echo -e "${GREEN}✓ Database reset${NC}"
    else
        echo -e "${YELLOW}⚠ Database exists but doesn't have required tables. Will be initialized.${NC}"
    fi
else
    echo -e "${YELLOW}⚠ Database doesn't exist yet. Will be created during import step.${NC}"
fi

# Step 2: Run code quality analysis
echo -e "\n${YELLOW}Step 2: Running checks${NC}"
# We expect this command to "fail" with exit code 1 when it finds issues - that's normal behavior
# Use || true to prevent script from exiting here due to set -e
python tests/test_code_quality_gate.py \
  --files ${TARGET_DIR} \
  --strict \
  --use-ruff \
  --format-check \
  --run-mypy \
  --run-bandit \
  --run-audit \
  --output markdown \
  --output-file ${OUTPUT_FILE} \
  --max-func-lines 15 \
  --max-nesting-depth 1 \
  --max-complexity 5 \
  --checks all || true

# Check if the output file exists and has content
if [ -f "${OUTPUT_FILE}" ] && [ -s "${OUTPUT_FILE}" ]; then
    echo -e "${GREEN}✓ Complete - issues found and saved to ${OUTPUT_FILE}${NC}"
else
    echo -e "${RED}✗ Analysis failed to generate any output${NC}"
    exit 1
fi

# Step 3: Parse issues and import into database
echo -e "\n${YELLOW}Step 3: Writing issues to database${NC}"
# First parse the issues into a structured format
python bs_task_parser.py || {
    echo -e "${YELLOW}⚠ Failed to create task list, trying direct import${NC}"
}

if [ -f "${STRUCTURED_FILE}" ]; then
    echo -e "${GREEN}✓ Tasks structured${NC}"
fi

# Then import directly from the original results file
echo -e "${YELLOW}Writing tasks to database...${NC}"
python -m task_engine.manage_tasks --import-md ${OUTPUT_FILE} || {
    echo -e "${RED}✗ Failed to import tasks into database${NC}"
    exit 1
}

# Verify tasks were imported
TASK_COUNT=$(sqlite3 ${DB_FILE} "SELECT COUNT(*) FROM tasks" 2>/dev/null || echo "0")
if [ "$TASK_COUNT" -gt "0" ]; then
    echo -e "${GREEN}✓ Successfully wrote ${TASK_COUNT} tasks into database${NC}"
else
    echo -e "${RED}✗ Failed to import tasks into database${NC}"
    exit 1
fi

# Step 4: Show summary
echo -e "\n${YELLOW}Step 4: Summary${NC}"
if command -v sqlite3 &> /dev/null; then
    echo -e "Total issues found: ${TASK_COUNT}"
    
    echo -e "\nIssues by type:"
    sqlite3 ${DB_FILE} "SELECT substr(code, 1, 2), COUNT(*) FROM tasks GROUP BY substr(code, 1, 2)" 2>/dev/null || echo "No issue codes found"
    
    echo -e "\nIssues by status:"
    sqlite3 ${DB_FILE} "SELECT status, COUNT(*) FROM tasks GROUP BY status" 2>/dev/null || echo "No status information found"
fi

echo -e "\n${BLUE}───────────────────────────────────────────────${NC}"
echo -e "${BLUE}Bad Vibe Scan complete! In future use these commands to manage tasks:${NC}"
echo -e "  • Task details:  python -m task_engine.manage_tasks --list"
echo -e "  • Fix a task:    python -m task_engine.manage_tasks --fix TASK_ID"
echo -e "  • Verify a task: python -m task_engine.manage_tasks --verify TASK_ID" 
echo -e "  • Batch process: python -m task_engine.manage_tasks --agent-loop --batch 5"
echo -e "${BLUE}───────────────────────────────────────────────${NC}"