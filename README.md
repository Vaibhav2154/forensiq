# ForensIQ 🛡️

<div align="center">

![ForensIQ Banner](https://img.shields.io/badge/ForensIQ-v1.0.0-00ff96?style=for-the-badge&logo=security&logoColor=white)

**Advanced AI-Powered Cybersecurity Platform for Threat Detection & Analysis**

[![MIT License](https://img.shields.io/badge/License-MIT-green.svg?style=flat-square)](https://choosealicense.com/licenses/mit/)
[![Python](https://img.shields.io/badge/Python-3.7+-blue.svg?style=flat-square)](https://python.org)
[![Next.js](https://img.shields.io/badge/Next.js-15-black.svg?style=flat-square)](https://nextjs.org)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-red.svg?style=flat-square)](https://attack.mitre.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-Latest-009688.svg?style=flat-square)](https://fastapi.tiangolo.com)

[🚀 Quick Start](#-quick-start) • [📖 Documentation](#-documentation) • [🛠️ Features](#-features) • [🤝 Contributing](#-contributing)

</div>

---

## 🎯 Overview

ForensIQ is a comprehensive, AI-enhanced cybersecurity platform that combines **real-time log analysis**, **MITRE ATT&CK framework integration**, and **intelligent threat detection** into a unified solution. Built for security professionals, incident responders, and SOC teams.

### 🌟 Why ForensIQ?

- **🧠 AI-Powered Analysis**: Leverages AWS Bedrock Titan embeddings and Google Gemini for intelligent threat detection
- **🎯 MITRE ATT&CK Integration**: Automatic mapping of security events to MITRE ATT&CK techniques
- **⚡ Real-time Monitoring**: Live log extraction from Windows Event Logs with MongoDB storage
- **🖥️ Modern Web Interface**: Next.js-powered dashboard with interactive threat visualization
- **🔧 CLI Tools**: Comprehensive command-line interface for automated operations
- **📊 Advanced Analytics**: Vector similarity search using ChromaDB for pattern recognition

## 🏗️ Architecture

ForensIQ consists of three main components:

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   🖥️ Client     │    │   🚀 Server      │    │  🤖 AI Agent   │
│   (Next.js)     │◄──►│   (FastAPI)      │◄──►│   (CLI Tool)    │
│                 │    │                  │    │                 │
│ • Dashboard     │    │ • REST API       │    │ • Log Monitor   │
│ • Threat Viz    │    │ • MITRE Search   │    │ • AI Analysis   │
│ • MITRE Search  │    │ • ChromaDB RAG   │    │ • MongoDB Sync  │
└─────────────────┘    └──────────────────┘    └─────────────────┘
```

## ✨ Features

### 🔍 **Threat Detection & Analysis**
- **Real-time Log Monitoring**: Continuous extraction from Windows Security/System Event Logs
- **AI-Powered Classification**: Automatic threat severity assessment using Gemini AI
- **MITRE ATT&CK Mapping**: Intelligent technique identification and categorization
- **Vector Similarity Search**: ChromaDB-powered pattern matching for anomaly detection

### 📊 **Interactive Dashboard**
- **Executive Summary**: High-level threat landscape overview
- **Timeline Visualization**: Chronological incident tracking
- **MITRE Framework Search**: Interactive technique exploration
- **Real-time Alerts**: Live threat notification system

### 🛠️ **CLI & Automation**
- **One-time Authentication**: Secure credential management with encryption
- **Profile-based Monitoring**: Customizable log source configurations
- **Scheduled Analysis**: Automated 5-minute interval processing
- **Export Capabilities**: JSON/CSV report generation

### 🔐 **Security & Integration**
- **Encrypted Storage**: PBKDF2 + Fernet encryption for sensitive data
- **MongoDB Integration**: Scalable log storage and retrieval
- **AWS Bedrock**: Enterprise-grade AI/ML capabilities
- **RESTful API**: Easy integration with existing security tools

## 🚀 Quick Start

### Prerequisites

- **Python 3.7+** 
- **Node.js 18+**
- **MongoDB** (local or cloud)
- **AWS Account** (for Bedrock access)

### 1️⃣ Clone the Repository

```bash
git clone https://github.com/Vaibhav2154/forensiq.git
cd forensiq
```

### 2️⃣ Set Up the AI Agent CLI

```bash
cd aiagent
pip install -e .

# Register and authenticate
forensiq-cli auth register --username your_username --email your_email
forensiq-cli auth login --username your_username
```

### 3️⃣ Configure Monitoring Profile

```bash
# Set up dynamic Windows Event Log monitoring
forensiq-cli profile setup-dynamic --sources security_events,system_events --interval 300

# Or file-based monitoring
forensiq-cli profile setup --log-path "C:\path\to\logs" --interval 300
```

### 4️⃣ Start the Backend Server

```bash
cd ../server
pip install -r requirements.txt

# Configure environment variables
cp .env.example .env
# Edit .env with your AWS credentials and MongoDB connection

# Start the server
python main.py
```

### 5️⃣ Launch the Web Dashboard

```bash
cd ../client
npm install
npm run dev
```

### 6️⃣ Begin Monitoring

```bash
cd ../aiagent

# Start real-time monitoring
forensiq-cli monitor --dynamic

# Or schedule automated analysis
forensiq-cli monitor --schedule
```

🎉 **You're ready!** Access the dashboard at `http://localhost:3000`

## 📖 Documentation

| Component | Description | Link |
|-----------|-------------|------|
| 🤖 **AI Agent** | CLI tool usage and automation | [CLI User Guide](aiagent/CLI_USER_GUIDE.md) |
| 🚀 **Server API** | Backend setup and deployment | [Deployment Guide](server/DEPLOYMENT_GUIDE.md) |
| 🎯 **MITRE Integration** | ATT&CK framework usage | [MongoDB Retrieval Guide](aiagent/MONGODB_RETRIEVAL_GUIDE.md) |
| 📊 **Monitoring** | Real-time log analysis | [Dynamic Monitoring Guide](aiagent/DYNAMIC_MONITORING_GUIDE.md) |

## 🛠️ Development

### Project Structure

```
forensiq/
├── 🤖 aiagent/          # CLI tool and AI agent
│   ├── cli_tool.py      # Main CLI interface
│   ├── ai_agent.py      # AI analysis engine
│   └── mongodb_service.py # Database operations
├── 🚀 server/           # FastAPI backend
│   ├── main.py          # API server
│   ├── services/        # AI and database services
│   └── routers/         # API endpoints
├── 🖥️ client/           # Next.js frontend
│   ├── app/             # App router pages
│   ├── components/      # React components
│   └── hooks/           # Custom hooks
└── 📄 docs/             # Documentation
```

### 🧪 Running Tests

```bash
# Test AI Agent
cd aiagent
python test_complete_functionality.py

# Test MongoDB integration
python test_mongodb.py

# Test server endpoints
cd ../server
python test_aws_bedrock.py
python test_rag.py
```

### 🐛 Debug Mode

Enable detailed logging:

```bash
# CLI with verbose output
forensiq-cli monitor --dynamic --verbose

# Server with debug mode
cd server
uvicorn main:app --reload --log-level debug
```

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### 🎯 Areas We Need Help

- [ ] **Additional Log Sources**: Support for Linux/macOS logs
- [ ] **Custom MITRE Techniques**: User-defined detection rules  
- [ ] **ML Model Training**: Enhanced threat classification
- [ ] **API Integrations**: SIEM platform connectors
- [ ] **Performance Optimization**: Large-scale log processing

### 🐛 Reporting Issues

Found a bug? Please [open an issue](https://github.com/Vaibhav2154/forensiq/issues) with:

- Detailed description
- Steps to reproduce
- Expected vs actual behavior
- System environment details

## 📊 Roadmap

### 🎯 Version 1.1 (Q4 2025)
- [ ] Multi-platform log support (Linux/macOS)
- [ ] Custom detection rule engine
- [ ] Advanced ML threat scoring
- [ ] SIEM integration APIs

### 🚀 Version 2.0 (Q1 2026)
- [ ] Distributed analysis cluster
- [ ] Real-time threat intelligence feeds
- [ ] Advanced visualization dashboard
- [ ] Enterprise SSO integration

## 📄 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **MITRE Corporation** for the ATT&CK framework
- **AWS Bedrock** for AI/ML capabilities  
- **Google Gemini** for advanced language processing
- **ChromaDB** for vector similarity search
- **FastAPI** and **Next.js** communities

## 🔗 Links

- **📧 Email**: vaibhavvaibhu2005@gmail.com
- **🐛 Issues**: [GitHub Issues](https://github.com/Vaibhav2154/forensiq/issues)
- **📖 Wiki**: [Project Wiki](https://github.com/Vaibhav2154/forensiq/wiki)
- **💬 Discussions**: [GitHub Discussions](https://github.com/Vaibhav2154/forensiq/discussions)

---

<div align="center">

**⭐ Star this repository if ForensIQ helps secure your environment!**

[![GitHub stars](https://img.shields.io/github/stars/Vaibhav2154/forensiq?style=social)](https://github.com/Vaibhav2154/forensiq/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/Vaibhav2154/forensiq?style=social)](https://github.com/Vaibhav2154/forensiq/network/members)

</div>
