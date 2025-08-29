# ForensIQ CLI Tool - User Guide

## Overview

The ForensIQ CLI Tool is an automated log analysis client that streamlines the process of sending logs to ForensIQ API endpoints with authentication, encryption, and intelligent scheduling. It features AI-powered analysis capabilities for enhanced threat detection.

## Features

- **One-time Authentication**: Secure token-based authentication with encrypted credential storage
- **Encrypted Communication**: All data transmission is encrypted for security
- **Automated Monitoring**: Configurable intervals for continuous log monitoring
- **AI Agent Integration**: Enhanced analysis with pattern learning and adaptive scheduling
- **User Profile Management**: Persistent configuration and preferences
- **Scheduled Analysis**: Background monitoring with intelligent interval adjustment

## Installation

1. Ensure you have Python 3.7+ installed
2. Install required dependencies:
   ```bash
   pip install -r cli_requirements.txt
   ```

## Quick Start

### 1. Authentication
```bash
# Login to ForensIQ (you'll be prompted for password)
python cli_tool.py auth login --username your_username

# Login with custom API URL
python cli_tool.py auth login --username your_username --api-url https://your-api.com
```

### 2. Profile Setup
```bash
# Setup monitoring profile
python cli_tool.py profile setup --log-path /path/to/logs/app.log --interval 300

# Setup with custom parameters
python cli_tool.py profile setup --log-path /var/log/auth.log --interval 600 --max-results 10
```

### 3. Send Logs for Analysis
```bash
# Analyze a specific log file
python cli_tool.py send --file /path/to/log.txt

# Analyze without AI enhancement
python cli_tool.py send --file /path/to/log.txt --no-enhance
```

### 4. Start Monitoring
```bash
# Start continuous monitoring
python cli_tool.py monitor --start

# Start scheduled analysis
python cli_tool.py monitor --schedule
```

## Advanced Usage

### AI Agent Management

#### Check AI Agent Status
```bash
python cli_tool.py agent status
```

#### Configure AI Agent
```bash
# Enable AI agent
python cli_tool.py agent configure --enable

# Disable AI agent
python cli_tool.py agent configure --disable

# Adjust learning parameters
python cli_tool.py agent configure --learning-threshold 5 --high-threat-interval 60
```

#### Reset AI Agent Learning Data
```bash
python cli_tool.py agent reset --confirm
```

### Enhanced Analysis
```bash
# Analyze with AI enhancement and save results
python cli_tool.py analyze --file /path/to/log.txt --enhanced --output results.json

# Analyze with AI agent
python cli_tool.py analyze --file /path/to/log.txt --ai-agent
```

## Configuration

The CLI tool stores configuration in your home directory under `.forensiq/`:

- `config.json`: Main configuration file
- `credentials.enc`: Encrypted authentication credentials
- `logs_cache/`: Cached log data and analysis results
- `ai_agent_state.json`: AI agent learning data and patterns

### Configuration Options

```json
{
  "api_url": "http://localhost:8000",
  "monitoring": {
    "log_path": "/path/to/logs",
    "interval": 300,
    "max_results": 5
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

## AI Agent Features

The AI Agent provides intelligent automation with the following capabilities:

### Pattern Learning
- Automatically detects and learns from log patterns
- Adapts to your environment's specific characteristics
- Builds confidence scores for different threat indicators

### Adaptive Scheduling
- Adjusts monitoring intervals based on threat levels
- Increases frequency during high-activity periods
- Optimizes resource usage during quiet periods

### Enhanced Analysis
- Context-aware threat detection
- Cross-correlation of events
- Automated response recommendations

### Threat Intelligence
- Maintains history of detected threats
- Identifies attack progression patterns
- Provides severity scoring and confidence metrics

## Security Features

### Encryption
- Credentials are encrypted using PBKDF2 with 100,000 iterations
- All API communications use secure protocols
- Local data is protected with user-specific encryption keys

### Authentication
- Token-based authentication with automatic refresh
- Secure credential storage
- Session management with timeout handling

## Error Handling

The CLI tool includes comprehensive error handling:

- Network connectivity issues
- Authentication failures
- File access problems
- API rate limiting
- Malformed log data

## Logging

The tool maintains detailed logs for troubleshooting:

- Application logs: `~/.forensiq/forensiq_cli.log`
- Error logs include stack traces and context
- Log levels: DEBUG, INFO, WARNING, ERROR, CRITICAL

## Performance Optimization

### Caching
- Analysis results are cached to avoid duplicate processing
- Intelligent cache invalidation based on file modification times
- Configurable cache size limits

### Batch Processing
- Multiple log files can be processed efficiently
- Automatic chunking for large files
- Memory-optimized processing

## Troubleshooting

### Common Issues

1. **Authentication Failures**
   ```bash
   # Clear stored credentials and re-authenticate
   rm ~/.forensiq/credentials.enc
   python cli_tool.py auth login --username your_username
   ```

2. **Connection Issues**
   ```bash
   # Test with verbose logging
   python cli_tool.py send --file test.log --verbose
   ```

3. **AI Agent Not Working**
   ```bash
   # Reset AI agent state
   python cli_tool.py agent reset --confirm
   python cli_tool.py agent configure --enable
   ```

### Debug Mode
```bash
# Enable debug logging
export FORENSIQ_DEBUG=1
python cli_tool.py [command]
```

## API Endpoints

The CLI tool interacts with the following ForensIQ API endpoints:

- `POST /auth/login` - User authentication
- `POST /analysis/logs` - Log analysis
- `GET /analysis/results/{id}` - Retrieve analysis results
- `POST /users/profile` - User profile management

## Examples

### Complete Workflow Example
```bash
# 1. Authenticate
python cli_tool.py auth login --username admin

# 2. Setup monitoring profile
python cli_tool.py profile setup --log-path /var/log/auth.log --interval 300

# 3. Configure AI agent
python cli_tool.py agent configure --enable --learning-threshold 3

# 4. Start monitoring
python cli_tool.py monitor --start
```

### Batch Analysis Example
```bash
# Analyze multiple files
for file in /var/log/*.log; do
    python cli_tool.py analyze --file "$file" --enhanced --output "results_$(basename $file).json"
done
```

## Best Practices

1. **Regular Monitoring**: Set appropriate intervals based on your security requirements
2. **AI Agent Training**: Allow the AI agent to learn from your environment for better accuracy
3. **Result Review**: Regularly review analysis results and adjust thresholds
4. **Backup Configuration**: Keep backups of your configuration and AI agent state
5. **Log Rotation**: Ensure your log files are properly rotated to avoid processing issues

## Support

For support and additional documentation, please refer to:
- Project repository: https://github.com/Vaibhav2154/forensiq
- API documentation: Available in the server module
- Log format specifications: See server documentation

## Version Information

Current version: 1.0.0
Compatible with ForensIQ API version: 1.0+
Python version requirement: 3.7+
