# Computer Using Agent (CUA) Project


## Setup

The code of `openai-cua-sample-app` was slightly modfied to use the Azure Foundry deployment of CUA.

1. **Create and activate a Python virtual environment**:
   ```bash
   conda env create -f env.yml
   conda activate cua
   
   cd openai-cua-sample-app
   pip install -r requirements.txt
   ```

2. **Configure API credentials**:
   Create a `.env` file in the project root with your API keys:
   ```bash
   AZURE_OPENAI_API_KEY=your-azure-api-key
   AZURE_OPENAI_ENDPOINT=https://your-resource-name.openai.azure.com
   AZURE_OPENAI_API_VERSION=2025-03-01-preview
   ```

3. **WSL specific**
    We are connecting to the docker container thrugh `vncviewer`. On WSL you will need to install the relevant packages with:
    ```bash
    sudo apt-get install -y tigervnc-viewer
    ```



### Docker Container

Build and run the containerized version:
```bash
docker build -t cua-sample-app .
docker run --rm -it --name cua-sample-app -p 5900:5900 --dns=1.1.1.3 -e DISPLAY=:99 cua-sample-app
```


## Running the app in docker

```bash
python cli.py --computer docker
```

To view the graphical interface inside Docker:
1. Connect using a VNC client (like TigerVNC):
   ```bash
   vncviewer localhost:5900
   ```
2. When prompted for a password, enter: `secret`
