# LogIQ CLI Tool - Complete User Guide

## 🚀 Overview

The LogIQ CLI Tool is a comprehensive automated log analysis client that provides AI-powered threat detection, real-time monitoring, and dynamic log extraction capabilities. It seamlessly integrates with your LogIQ server to provide continuous security monitoring with MongoDB storage and intelligent analysis.

## ✨ Key Features

- **🔐 Secure Authentication**: One-time login with encrypted credential storage
- **📊 Dynamic Log Extraction**: Real-time extraction from Windows Event Logs
- **🤖 AI-Powered Analysis**: Intelligent threat detection with MITRE ATT&CK mapping
- **📈 Real-time Monitoring**: Automated 5-minute interval monitoring with MongoDB storage
- **🔄 Adaptive Scheduling**: AI agent adjusts monitoring frequency based on threat levels
- **📋 Data Management**: Comprehensive MongoDB data retrieval and export capabilities
- **🛡️ Enhanced Security**: PBKDF2 encryption and secure token management

## 📦 Installation & Setup

### Prerequisites

- Python 3.7 or higher
- LogIQ server running (FastAPI backend)
- MongoDB database configured
- Windows system (for dynamic log extraction)

### Installation

1. **Clone or download the aiagent folder**
2. **Install dependencies**:
   ```bash
   cd aiagent
   pip install -r cli_requirements.txt
   ```

3. **Verify installation**:
   ```bash
   python cli_tool.py --help
   ```

### Dependencies

The CLI tool requires the following packages:
- `aiohttp>=3.8.0` - Async HTTP client
- `aiofiles>=23.0.0` - Async file operations
- `cryptography>=41.0.0` - Encryption for credentials
- `schedule>=1.2.0` - Task scheduling
- `requests>=2.31.0` - HTTP requests
- `motor>=3.3.0` - Async MongoDB driver
- `pymongo>=4.5.0` - MongoDB driver
- `python-dotenv>=1.0.0` - Environment variables
- `pydantic>=2.0.0` - Data validation
- `rich>=13.0.0` - Beautiful CLI output

## 🔐 Authentication

### User Registration

```bash
# Register a new user account
python cli_tool.py auth register --username <username> --email <email>

# Example
python cli_tool.py auth register --username security_analyst --email analyst@company.com
```

### User Login

```bash
# Login with username (password will be prompted)
python cli_tool.py auth login --username <username>

# Login with custom API URL
python cli_tool.py auth login --username <username> --api-url https://your-api.com

# Example
python cli_tool.py auth login --username security_analyst
```

### Profile Management

```bash
# Get your user profile information
python cli_tool.py auth profile
```

**Security Features:**
- Credentials are encrypted using PBKDF2 with 100,000 iterations
- Tokens are automatically refreshed when expired
- Secure credential storage in `~/.logiq/credentials.enc`

## 📊 Profile Management

### File-based Monitoring Setup

```bash
# Setup monitoring for a specific log file
python cli_tool.py profile setup --log-path <path> --interval <seconds> [options]

# Example: Monitor Windows Security log every 5 minutes
python cli_tool.py profile setup --log-path "C:\Windows\System32\winevt\Logs\Security.evtx" --interval 300 --max-results 10
```

**Options:**
- `--log-path`: Path to log file to monitor
- `--interval`: Monitoring interval in seconds (default: 300)
- `--max-results`: Maximum MITRE techniques to return (default: 5)
- `--no-enhance`: Disable AI enhancement
- `--no-ai-agent`: Disable AI agent integration

### Dynamic Monitoring Setup

```bash
# Setup dynamic monitoring for system sources
python cli_tool.py profile setup-dynamic --sources <sources> --interval <seconds>

# List available log sources
python cli_tool.py profile setup-dynamic --list-sources

# Example: Monitor security and system events
python cli_tool.py profile setup-dynamic --sources security_events,system_events --interval 300
```

**Available Dynamic Sources:**
- `security_events` - Windows Security Event Log
- `system_events` - Windows System Event Log
- `application_events` - Windows Application Event Log
- `powershell_logs` - PowerShell Execution Logs
- `process_monitor` - Process creation/termination monitoring
- `network_connections` - Active network connections
- `file_system_activity` - File system changes

### Profile Management Commands

```bash
# Check current profile status
python cli_tool.py profile status

# Update profile settings
python cli_tool.py profile update [options]

# Options for profile update:
# --interval <seconds> - Change monitoring interval
# --max-results <num> - Change max results
# --enable-ai - Enable AI enhancement
# --disable-ai - Disable AI enhancement
# --enable-agent - Enable AI agent
# --disable-agent - Disable AI agent
```

## 🔍 Log Analysis

### Single File Analysis

```bash
# Analyze a specific log file
python cli_tool.py analyze --file <log_file> [options]

# Basic analysis
python cli_tool.py analyze --file /path/to/log.txt

# Enhanced analysis with AI agent
python cli_tool.py analyze --file /path/to/log.txt --enhanced --ai-agent --output results.json
```

**Options:**
- `--file`: Path to log file to analyze
- `--enhanced`: Enable enhanced AI analysis
- `--ai-agent`: Use AI agent for analysis (default: true)
- `--output`: Save results to file (JSON format)

### Send Logs for Analysis

```bash
# Send log file for analysis
python cli_tool.py send --file <log_file> [options]

# Example
python cli_tool.py send --file /var/log/auth.log

# Send without AI enhancement
python cli_tool.py send --file /var/log/auth.log --no-enhance
```

## 📈 Monitoring

### File-based Monitoring

```bash
# Start automated file monitoring
python cli_tool.py monitor --start

# Start with custom interval
python cli_tool.py monitor --start --interval 600
```

### Dynamic System Monitoring

```bash
# Start dynamic system monitoring
python cli_tool.py monitor --dynamic

# Start with specific sources
python cli_tool.py monitor --dynamic --sources security_events,process_monitor

# Start with custom interval
python cli_tool.py monitor --dynamic --interval 300
```

### Scheduled Analysis

```bash
# Start scheduled analysis
python cli_tool.py monitor --schedule
```

### Automated Monitoring Setup

```bash
# Enable fully automated monitoring (no password prompts)
python cli_tool.py monitor --dynamic --enable-auto
```

**What happens during monitoring:**
1. ✅ Authenticates with LogIQ server
2. ✅ Creates monitoring session in MongoDB
3. ✅ Every 5 minutes: extracts new log entries
4. ✅ Sends logs to `/api/v1/analyze` endpoint
5. ✅ AI agent enhances analysis with threat intelligence
6. ✅ Stores complete results in MongoDB
7. ✅ Adjusts intervals based on threat levels
8. ✅ Continues until stopped (Ctrl+C)

## 🤖 AI Agent Management

### AI Agent Status

```bash
# Check AI agent status and learning progress
python cli_tool.py agent status
```

### AI Agent Configuration

```bash
# Enable AI agent
python cli_tool.py agent configure --enable

# Disable AI agent
python cli_tool.py agent configure --disable

# Configure learning parameters
python cli_tool.py agent configure --learning-threshold 5 --high-threat-interval 60

# Advanced configuration
python cli_tool.py agent configure --learning-threshold 0.8 --high-threat-interval 120 --medium-threat-interval 300
```

### AI Agent Reset

```bash
# Reset AI agent learning data
python cli_tool.py agent reset --confirm
```

**AI Agent Features:**
- **Pattern Learning**: Automatically detects and learns from log patterns
- **Adaptive Scheduling**: Adjusts monitoring intervals based on threat levels
- **Enhanced Analysis**: Context-aware threat detection
- **Threat Intelligence**: Maintains history of detected threats
- **Confidence Scoring**: Provides confidence metrics for threat assessments

## 📋 Data Management

### MongoDB Collections

The CLI tool stores data in three main MongoDB collections:

1. **`analysis`** - Log analysis results with MITRE ATT&CK techniques
2. **`sessions`** - Active monitoring configurations and statistics  
3. **`users`** - User authentication and profile information

### Data Retrieval Commands

```bash
# List all available collections
python cli_tool.py data list

# Get collection statistics
python cli_tool.py data stats
```

### Analysis Data Retrieval

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

### Monitoring Sessions Retrieval

```bash
# Get latest 10 monitoring sessions
python cli_tool.py data sessions

# Get latest 25 sessions
python cli_tool.py data sessions --limit 25

# Export sessions to file
python cli_tool.py data sessions --export sessions_data.json --limit 50

# Export to CSV
python cli_tool.py data sessions --export sessions_data.csv --format csv
```

## 🔧 Advanced Features

### Pre-RAG Classifier

```bash
# Test classifier on log file
python cli_tool.py classifier test --file <log_file> [options]

# Example
python cli_tool.py classifier test --file sample.log --output filtered_logs.json --stats
```

**Options:**
- `--file`: Log file to test
- `--output`: Output file for filtered logs
- `--stats`: Show detailed statistics

### Machine Learning Models

The CLI tool includes several ML models in the `Scripts/` directory:

- **Threat Classification Models**: Pre-trained models for threat detection
- **Cost-Sensitive Training**: Models optimized for security use cases
- **Confidence Analysis**: Models for assessing threat confidence levels
- **Robustness Testing**: Tools for testing model performance

### Dynamic Log Extraction

The dynamic log extractor supports multiple log sources:

**Windows Event Logs:**
- Security Events (login attempts, privilege changes)
- System Events (service starts, errors)
- Application Events (application-specific logs)
- PowerShell Logs (script execution)

**System Monitoring:**
- Process Creation/Termination
- Network Connections
- File System Activity
- Registry Changes

## 🛠️ Configuration

### Configuration Files

The CLI tool stores configuration in `~/.logiq/`:

- `config.json` - Main configuration file
- `credentials.enc` - Encrypted authentication credentials
- `logs_cache/` - Cached log data and analysis results
- `ai_agent_state.json` - AI agent learning data and patterns

### Configuration Options

```json
{
  "api_url": "http://localhost:8000",
  "monitoring": {
    "log_path": "/path/to/logs",
    "interval": 300,
    "max_results": 5,
    "use_dynamic_extraction": false,
    "sources": ["security_events", "system_events"]
  },
  "ai_agent_enabled": true,
  "ai_agent_config": {
    "learning_threshold": 3,
    "high_threat_interval": 60,
    "medium_threat_interval": 300,
    "low_threat_interval": 3600
  }
}
```

## 📊 Examples & Workflows

### Complete Security Monitoring Setup

```bash
# 1. Register and login
python cli_tool.py auth register --username security_analyst --email analyst@company.com
python cli_tool.py auth login --username security_analyst

# 2. Setup dynamic monitoring
python cli_tool.py profile setup-dynamic --sources security_events,system_events,process_monitor --interval 300

# 3. Configure AI agent
python cli_tool.py agent configure --enable --learning-threshold 0.8

# 4. Start monitoring
python cli_tool.py monitor --dynamic

# 5. Check results
python cli_tool.py data analysis --limit 10
```

### Batch Analysis Workflow

```bash
# Analyze multiple log files
for file in /var/log/*.log; do
    python cli_tool.py analyze --file "$file" --enhanced --output "results_$(basename $file).json"
done
```

### Data Export Workflow

```bash
# Export all analysis data for reporting
python cli_tool.py data analysis --export security_report.csv --format csv --limit 1000

# Export monitoring sessions
python cli_tool.py data sessions --export sessions_report.json --limit 50
```

## 🚨 Troubleshooting

### Common Issues

**1. Authentication Failures**
```bash
# Clear stored credentials and re-authenticate
rm ~/.logiq/credentials.enc
python cli_tool.py auth login --username your_username
```

**2. Connection Issues**
```bash
# Test with verbose logging
python cli_tool.py send --file test.log --verbose

# Check server status
python cli_tool.py auth profile
```

**3. AI Agent Not Working**
```bash
# Reset AI agent state
python cli_tool.py agent reset --confirm
python cli_tool.py agent configure --enable
```

**4. MongoDB Connection Issues**
```bash
# Check MongoDB service status
python cli_tool.py data stats

# Verify server configuration
python cli_tool.py data list
```

**5. Dynamic Log Extraction Issues**
```bash
# Check available sources
python cli_tool.py profile setup-dynamic --list-sources

# Test specific source
python cli_tool.py monitor --dynamic --sources security_events
```

### Debug Mode

```bash
# Enable debug logging
export LOGIQ_DEBUG=1
python cli_tool.py [command]
```

### Log Files

The tool maintains detailed logs for troubleshooting:
- Application logs: `~/.logiq/logiq_cli.log`
- Error logs include stack traces and context
- Log levels: DEBUG, INFO, WARNING, ERROR, CRITICAL

## 🔒 Security Features

### Encryption
- **PBKDF2 Key Derivation**: 100,000 iterations for credential storage
- **Fernet Symmetric Encryption**: Secure local data protection
- **JWT Token Authentication**: Secure server communication
- **Session Management**: Automatic token refresh and validation

### Data Protection
- **Encrypted Credential Storage**: Passwords never stored in plain text
- **Secure API Communication**: All transmissions encrypted
- **Local Data Protection**: User-specific encryption keys
- **Session Timeout**: Automatic session expiration

## 📈 Performance Optimization

### Caching
- **Analysis Results**: Cached to avoid duplicate processing
- **Intelligent Cache Invalidation**: Based on file modification times
- **Configurable Cache Size**: Memory-optimized processing

### Batch Processing
- **Multiple Log Files**: Efficient batch processing
- **Automatic Chunking**: Large files processed in chunks
- **Memory Optimization**: Streaming processing for large datasets

## 🎯 Best Practices

1. **Regular Monitoring**: Set appropriate intervals based on security requirements
2. **AI Agent Training**: Allow the AI agent to learn from your environment
3. **Result Review**: Regularly review analysis results and adjust thresholds
4. **Backup Configuration**: Keep backups of configuration and AI agent state
5. **Log Rotation**: Ensure log files are properly rotated
6. **Security Updates**: Keep the CLI tool and dependencies updated
7. **Network Security**: Use secure connections for API communication

## 📞 Support & Resources

### Documentation
- **Quick Start Guide**: `QUICK_START_GUIDE.md`
- **Feature Summary**: `CLI_FEATURE_SUMMARY.md`
- **Dynamic Monitoring**: `DYNAMIC_MONITORING_GUIDE.md`
- **MongoDB Retrieval**: `MONGODB_RETRIEVAL_GUIDE.md`
- **Implementation Summary**: `IMPLEMENTATION_SUMMARY.md`

### Testing
- **Complete Functionality Test**: `python test_complete_functionality.py`
- **CLI Test**: `python test_cli.py`
- **MongoDB Test**: `python test_mongodb.py`

### Version Information
- **Current Version**: 1.0.0
- **Compatible with LogIQ API**: 1.0+
- **Python Requirement**: 3.7+
- **Supported OS**: Windows (primary), Linux, macOS

## 🚀 Getting Started Checklist

- [ ] Install Python 3.7+ and dependencies
- [ ] Start LogIQ server (FastAPI backend)
- [ ] Register user account
- [ ] Login to CLI tool
- [ ] Setup monitoring profile (file-based or dynamic)
- [ ] Configure AI agent
- [ ] Start monitoring
- [ ] Check results in MongoDB
- [ ] Export data for analysis

---

**🎉 You're now ready to use the LogIQ CLI Tool for comprehensive automated log analysis and threat detection!**