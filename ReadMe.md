# Log Analysis & CTI Tool

A comprehensive Python-based tool for analyzing web server logs, enriching data with Cyber Threat Intelligence (CTI), and generating detailed security reports with AI-powered insights.

## Features

- **Log Parsing**: Supports multiple log formats (Common, Combined, JSON, Custom)

- **Threat Intelligence Integration**:
  
  - AbuseIPDB API integration
  
  - VirusTotal API integration
  
  - Cisco Talos Intelligence

- **AI-Powered Analysis**: Local Llama integration via Ollama for threat explanation

- **Risk Scoring**: Comprehensive risk assessment based on multiple factors

- **Detailed Reporting**: Markdown reports with executive summaries and recommendations

- **GUI Interface**: User-friendly graphical interface (optional)

- **Cross-Platform**: Works on Windows, macOS, and Linux

## Prerequisites

- Python 3.8+

- Ollama (for local AI features)

- API keys for:
  
  - VirusTotal (required)
  
  - AbuseIPDB (optional)

### 2. Create Virtual Environment

bash

### Windows

python -m venv venv
.\venv\Scripts\activate

### Linux/macOS

python3 -m venv venv
source venv/bin/activate

### 3. Install Dependencies

bash

pip install -r requirements.txt

### 4. Install Ollama (for Local AI)

bash

##### Download from https://ollama.com/

##### Or use package manager:

##### Windows (download installer)

#### macOS

brew install ollama

#### Linux

curl -fsSL https://ollama.com/install.sh | sh

### 5. Download AI Models

bash

# Download preferred models

ollama pull llama3

ollama run llama3

ollama pull phi

ollama pull mistral

### Graphical User Interface

bash

# Launch GUI

python main.py --gui
