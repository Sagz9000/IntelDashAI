

# Cyber Threat Analysis & RAG Assistant
This application is a comprehensive cybersecurity analysis tool that leverages the MITRE ATT&CK framework and a Retrieval-Augmented Generation (RAG) system to provide deep threat intelligence insights. It allows users to visualize threat coverage, analyze documents and code for threat actor techniques, and interact with an AI assistant to query cybersecurity knowledge.

🚀 **Key Features**
MITRE ATT&CK Matrix Visualization: Fetches live ATT&CK data to generate an interactive matrix showing tactics, techniques, and your current detection coverage. The matrix can be exported to a .csv file.
Detection Coverage Analysis: Ingests YAML-based detection rules from local or Git sources to map existing detections against the ATT&CK framework, identifying strengths and gaps.

# Multi-Source Content Analysis:
Documents: Upload .pdf and .docx files to extract text, identify MITRE Technique IDs (T-codes), and map them to known threat groups.
URLs: Analyze the content of any webpage for T-codes and associated intelligence.
GitHub Repositories: Scan code repositories to find T-codes, extract relevant code snippets, and embed the content for AI analysis.
# AI-Powered RAG Assistant:
Engage in a natural language conversation with a specialized AI to ask complex cybersecurity questions.
The AI can query two distinct knowledge bases: the entire MITRE ATT&CK framework or the content you have uploaded.
The AI is prompted to act as a cybersecurity expert with the persona.
Reporting & Data Export: Generate .csv reports for various datasets, including technique coverage, searches missing ATT&CK tags, and OS-specific detection lists.

## Disclaimer
This is a POC meant primarily for a lab and utilizing an AI agent for intel.  It is a learning exercise and not meant to be perfect.
Configuration files to build the docker containers are provided



![matrix](aidashboard/matrix.png)

## Overview

The project consists of several key components:

- **Web Interface & Data Visualization:**  
  A user-friendly front end (implemented in HTML/JS) that displays:
  - User data management information.
  - Analysis of threat intelligence documents linked with the MITRE ATT&CK framework.
![ttpenrichpre](aidashboard/prequery.png)
![ttpenrich](aidashboard/afterquery.png)
   - Chat trained on documents provided  
![chat](aidashboard/aiquestion.png)
  - Analysis of repo and documents
![doc](aidashboard/postanalyzeddoc.png)
  - Analysis of websites
  -
  - ![site](aidashboard/urlprocessing.png)
  - Query Chroma Vector DB to see structure for chunking
![dbcontent](aidashboard/dbcontent.png)

- **Customize Ollama:**  
![model](aidashboard/model.png)
  - If not using nvidia gpu modify the settings for gpu/cpu type
    
![set](aidashboard/ollamachromadb.png)
 - Change Prompt settings
 - 
![prmt](aidashboard/promptsettings.png)



- **Backend Processing:**  
  A Flask-based web application that:
  - Processes incoming requests.
  - Coordinates document analysis and integrates AI/model inference via external services (e.g., Ollama).
  - Manages synthetic data generation for simulation exercises.

- **Synthetic Data Generation:**
- ![synthetic](aidashboard/synthetics.png)

  The `synthetic.py` script generates realistic cybersecurity events by:
  - Creating network log entries with detailed attributes such as timestamps, IP addresses, ports, and protocol details.
  - Augmenting these events with MITRE ATT&CK techniques to simulate real-world threat scenarios.
  - Exporting the generated data into a JSON file (`cybersecurity_synthetic_data_with_mitre.json`).

- **Containerization & Microservices:**  
  The project uses Docker to containerize its services for reliable, reproducible deployments:
  - **Main Application Container (Dockerfile):**  
    Builds a Python environment based on Debian Bookworm slim, installs all required dependencies from `requirements.txt`, and sets up the Flask application.
    
  - **ChromaDB Container (Dockerfile.chromadb):**  
    Sets up ChromaDB—a vector search database used to support document analysis and other analytics features. This container also ensures necessary connectivity by installing tools like netcat.

- **Service Initialization:**  
  The `entrypoint.sh` script manages startup procedures for auxiliary services such as Ollama:
  - Installs prerequisites (e.g., curl).
  - Sets up environment variables.
  - Ensures that the Ollama service is reachable before pulling and running the required models.
  - Finally, it executes the main command to start the application.

📖 API Endpoints
The application exposes a REST API for its core functionalities.
```
Method	Endpoint	Description
GET	/api/matrix	Returns the full, processed MITRE ATT&CK matrix data as JSON.
POST	/api/analyze_document	Uploads and analyzes .pdf or .docx files for T-codes and threat groups.
POST	/api/analyze_url	Fetches and analyzes a URL's content for T-codes.
POST	/api/analyze_github_repo	Analyzes a GitHub repository for T-codes and embeds its content.
POST	/api/ai_query	Sends a natural language query to the RAG-powered AI assistant.
GET	/api/techniques/{technique_id}/groups	Returns the threat groups known to use a specific technique.
GET	/api/technique_usage/{group_id}/{technique_id}	Describes how a specific group uses a specific technique.
GET	/api/missing_tags	Finds detection searches that are not mapped to a MITRE technique.
GET	/api/os_distribution	Shows the breakdown of detection searches by operating system.
GET	/api/user_data	Retrieves all content that has been uploaded and embedded by the user.
```

## File Structure

Below is a breakdown of key files in this repository:
![docker](/aidashboard/dockerview.png)


- **Dockerfile**  
  Builds the container image for the Flask-based web application. It installs system dependencies, copies your code into the container, and exposes the necessary port (e.g., 5000).

- **Dockerfile.chromadb**  
  Builds a dedicated container for ChromaDB using an official base image (version 0.4.24). This file also installs netcat to facilitate connectivity checks.

- **entrypoint.sh**  
  A shell script that:
  - Installs any missing prerequisites.
  - Sets up the environment for the Ollama service.
  - Starts the `ollama serve` process in the background.
  - Checks that Ollama is running before proceeding with pulling models and launching the main application.

- **requirements.txt**  
  Lists all Python dependencies required by the Flask application, including:
  - Flask (for web serving)
  - PyYAML, lxml, BeautifulSoup4, python-docx, PyPDF2 (for data parsing and document analysis)
  - requests & Werkzeug (for HTTP handling and server utilities)
  - ollama & chromadb (for integration with AI model inference and vector database functionalities)
  - langchain (to help chain language processing tasks)
  - numpy (with a specific version for compatibility)

- **synthetic.py**  
  Contains the core logic to generate synthetic cybersecurity data:
  - Creates entries that mimic network logs.
  - Augments events with MITRE ATT&CK techniques and threat group information.
  - Exports the generated data into a JSON file (`cybersecurity_synthetic_data_with_mitre.json`).

## Getting Started

To run the platform locally, follow these steps:

1. **Clone the Repository:**
   ```
   git clone (https://github.com/Sagz9000/IntelDashAI.git)
   cd IntelDashAI
   ```

2. **Build and Run Docker Containers:**
   - Build the main application container:
     ```
     docker build -t cybersecurity-app .
     ```
   - Build the ChromaDB container:
     ```
     docker build -f Dockerfile.chromadb -t chromadb .
     ```
   - Ensure that the `entrypoint.sh` script has executable permissions:
     ```
     chmod +x entrypoint.sh
     ```
   - Start the containers (you might use Docker Compose if you configure inter-container communication):
     ```
     docker run -d --name ollama-service -p 11434:8080 your-ollama-image
     docker run -d --name chromadb -p 8000:8000 chromadb
     docker run -d --name app -p 5000:5000 cybersecurity-app
     ```

3. **Generate Synthetic Data:**
   Run the synthetic data generator:
   ```
   python synthetic.py
   ```
   The generated file (`cybersecurity_synthetic_data_with_mitre.json`) will contain your simulated cybersecurity events.

## Future Enhancements

- Expand the web interface to include advanced filtering and visualization tools.
- Integrate more detailed logging and error handling for improved diagnostics.
- Extend synthetic data generation with additional event types or dynamic threat scenarios.


