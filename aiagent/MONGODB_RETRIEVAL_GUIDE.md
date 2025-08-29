# MongoDB Data Retrieval Guide

## Overview

The ForensIQ CLI tool now provides comprehensive MongoDB data retrieval capabilities. You can view, export, and analyze all the data stored by the monitoring system including analysis results, monitoring sessions, and collection statistics.

## 📋 Available Collections

### 1. Analysis Collection (`analysis`)
- **Purpose**: Stores all log analysis results from the ForensIQ API
- **Contains**: 
  - MITRE ATT&CK technique matches
  - AI-enhanced threat analysis
  - User analysis history
  - Threat scores and confidence ratings
  - Log source information

### 2. Monitoring Sessions Collection (`sessions`)
- **Purpose**: Tracks active and historical monitoring sessions
- **Contains**:
  - Session configuration details
  - Log source selections
  - Monitoring intervals and status
  - Analysis counts and timestamps

### 3. Users Collection (`users`)
- **Purpose**: User account and authentication data
- **Contains**:
  - User profiles and authentication info
  - Account creation and activity data

## 🚀 Commands

### List Available Collections
```bash
python cli_tool.py data list
```
Shows all available MongoDB collections with descriptions.

### Retrieve Analysis Data
```bash
# Get latest 10 analysis records
python cli_tool.py data analysis

# Get latest 50 analysis records
python cli_tool.py data analysis --limit 50

# Filter by specific user
python cli_tool.py data analysis --user admin --limit 20

# Export to JSON file
python cli_tool.py data analysis --export analysis_data.json --limit 100

# Export to CSV file
python cli_tool.py data analysis --export analysis_data.csv --format csv --limit 100
```

### Retrieve Monitoring Sessions
```bash
# Get latest 10 monitoring sessions
python cli_tool.py data sessions

# Get latest 25 sessions
python cli_tool.py data sessions --limit 25

# Export sessions to file
python cli_tool.py data sessions --export sessions_data.json --limit 50

# Export to CSV format
python cli_tool.py data sessions --export sessions_data.csv --format csv
```

### View Collection Statistics
```bash
# Show statistics for all collections
python cli_tool.py data stats
```
Displays:
- Total record counts
- Storage sizes
- Last update timestamps

## 📊 Sample Output

### Analysis Data Display
```
📊 Analysis Data (5 records):
================================================================================

1. Analysis ID: 64f7b8c9e123456789abcdef
   User: admin
   Timestamp: 2025-08-29T15:30:45.123Z
   Log Source: security_events
   Summary: Detected multiple failed login attempts and privilege escalation...
   MITRE Techniques (3):
     • T1078: Valid Accounts
     • T1110: Brute Force
     • T1548: Abuse Elevation Control Mechanism
   AI Enhanced: ✓
   Threat Score: 0.87
```

### Monitoring Sessions Display
```
🔍 Monitoring Sessions (3 records):
================================================================================

1. Session ID: 64f7b8c9e123456789abcdef
   User: admin
   Started: 2025-08-29T14:00:00.000Z
   Status: active
   Interval: 300 seconds
   Log Sources: security_events, system_events
   Total Analyses: 24
   Last Analysis: 2025-08-29T15:25:00.000Z
```

### Collection Statistics Display
```
📈 MongoDB Collection Statistics:
==================================================

🗃️  Log Analysis:
   Total Records: 1,247
   Storage Size: 2,456,789 bytes
   Last Updated: 2025-08-29T15:30:45.123Z

🗃️  Monitoring Sessions:
   Total Records: 15
   Storage Size: 45,632 bytes
   Last Updated: 2025-08-29T15:25:12.456Z
```

## 🔐 Authentication Required

All data retrieval commands require authentication. Make sure to login first:

```bash
# Login before retrieving data
python cli_tool.py auth login --username your_username

# Then retrieve data
python cli_tool.py data analysis --limit 20
```

## 📁 Export Formats

### JSON Export
- **Advantages**: Preserves all data types and nested structures
- **Best For**: Further processing, backup, or detailed analysis
- **Example**: Complete MITRE technique objects with all metadata

### CSV Export
- **Advantages**: Easy to open in Excel, suitable for quick analysis
- **Best For**: Reporting, spreadsheet analysis, data visualization
- **Note**: Complex fields are converted to strings

## 🔍 Filtering and Limits

### Limit Records
Use `--limit` to control how many records to retrieve:
```bash
python cli_tool.py data analysis --limit 5    # Get 5 records
python cli_tool.py data analysis --limit 100  # Get 100 records
```

### Filter by User
For analysis data, filter by specific username:
```bash
python cli_tool.py data analysis --user admin --limit 50
python cli_tool.py data analysis --user analyst01 --limit 25
```

## 💡 Usage Tips

### 1. Regular Data Review
```bash
# Daily review of recent analyses
python cli_tool.py data analysis --limit 50

# Check monitoring session health
python cli_tool.py data sessions --limit 10
```

### 2. Data Backup
```bash
# Backup all analysis data
python cli_tool.py data analysis --export backup_analysis_$(date +%Y%m%d).json --limit 10000

# Backup monitoring sessions
python cli_tool.py data sessions --export backup_sessions_$(date +%Y%m%d).json --limit 1000
```

### 3. Reporting
```bash
# Generate CSV reports for management
python cli_tool.py data analysis --export monthly_report.csv --format csv --limit 500

# Export user-specific data
python cli_tool.py data analysis --user security_team --export security_analysis.csv --format csv
```

### 4. Troubleshooting
```bash
# Check collection health
python cli_tool.py data stats

# Review recent monitoring activity
python cli_tool.py data sessions --limit 5

# Check for failed analyses
python cli_tool.py data analysis --limit 20 | grep -i error
```

## 🚨 Error Handling

The system handles various error conditions:

- **Authentication Failures**: Clear error messages with login instructions
- **Network Issues**: Retry logic with exponential backoff
- **Empty Collections**: Graceful handling with informative messages
- **Export Failures**: Detailed error reporting with suggestions

## 🔄 Integration with Monitoring

The data retrieval system works seamlessly with the monitoring system:

1. **Real-time Data**: Retrieve data that's being generated by active monitoring
2. **Historical Analysis**: Access complete historical records
3. **Performance Tracking**: Monitor system performance through statistics
4. **Audit Trail**: Complete audit trail of all monitoring activities

## 🛠️ Advanced Usage

### Combining Commands
```bash
# Check stats first, then export based on findings
python cli_tool.py data stats
python cli_tool.py data analysis --export full_backup.json --limit 5000

# Monitor active sessions, then get recent analysis
python cli_tool.py data sessions --limit 5
python cli_tool.py data analysis --limit 10
```

### Automated Scripts
Create scripts for regular data management:

```bash
#!/bin/bash
# Daily backup script
DATE=$(date +%Y%m%d)
python cli_tool.py data analysis --export "daily_analysis_$DATE.json" --limit 1000
python cli_tool.py data sessions --export "daily_sessions_$DATE.json" --limit 100
echo "Daily backup completed: $DATE"
```

This comprehensive data retrieval system gives you complete visibility into all the data stored in your MongoDB collections, enabling effective monitoring, reporting, and analysis of your ForensIQ system's activities.
