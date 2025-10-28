# Deploying to Wikimedia Toolforge

This guide explains how to deploy the Folder-to-Commons-Uploader to Wikimedia Toolforge.

## Prerequisites

### 1. Get Toolforge Access
1. Create a Wikimedia developer account at https://developer.wikimedia.org/
2. Request a Toolforge account through https://wikitech.wikimedia.org/
3. Once approved, you'll receive SSH access

### 2. Create a Tool Account
1. Log in to Toolforge: `ssh YOUR_USERNAME@login.toolforge.org`
2. Create a new tool: `toolforge tool create YOUR_TOOL_NAME`
3. Enter the tool account: `become YOUR_TOOL_NAME`

## Deployment Steps

### Step 1: Clone Your Repository
```bash
# SSH into Toolforge
ssh YOUR_USERNAME@login.toolforge.org

# Become your tool account
become YOUR_TOOL_NAME

# Clone your repository
git clone https://github.com/YOUR_USERNAME/Folder-to-Commons-Uploader.git
cd Folder-to-Commons-Uploader
```

### Step 2: Set Up Environment Variables
```bash
# Create .env file with your credentials
cat > .env << EOF
COMMONS_USERNAME=YourWikimediaUsername
COMMONS_PASSWORD=YourBotPassword
COMMONS_USER_AGENT=YourToolName/1.0 (contact@example.com)
EOF

# Make sure .env is not readable by others
chmod 600 .env
```

**Important**: Get a bot password from https://commons.wikimedia.org/wiki/Special:BotPasswords

### Step 3: Build and Deploy with Docker (Recommended)

#### Option A: Using Toolforge Build Service (Easiest)
```bash
# Build the Docker image
toolforge build start https://github.com/YOUR_USERNAME/Folder-to-Commons-Uploader.git

# Wait for build to complete
toolforge build show

# Deploy the webservice
toolforge webservice start \
  --backend=kubernetes \
  buildservice YOUR_TOOL_NAME

# Check status
toolforge webservice status
```

#### Option B: Using Local Dockerfile
```bash
# Build the image locally
docker build -t YOUR_TOOL_NAME .

# Push to Toolforge registry
docker tag YOUR_TOOL_NAME docker-registry.tools.wmflabs.org/YOUR_TOOL_NAME:latest
docker push docker-registry.tools.wmflabs.org/YOUR_TOOL_NAME:latest

# Deploy
toolforge webservice start \
  --backend=kubernetes \
  --image=docker-registry.tools.wmflabs.org/YOUR_TOOL_NAME:latest
```

### Step 4: Set Up Background Job for monitor.py
The file monitor needs to run continuously in the background.

```bash
# Create a job file for the monitor
cat > monitor-job.yaml << EOF
apiVersion: batch/v1
kind: Job
metadata:
  name: folder-monitor
spec:
  template:
    spec:
      containers:
      - name: monitor
        image: docker-registry.tools.wmflabs.org/YOUR_TOOL_NAME:latest
        command: ["python3", "monitor.py"]
        volumeMounts:
        - name: data
          mountPath: /data/project/YOUR_TOOL_NAME
      volumes:
      - name: data
        hostPath:
          path: /data/project/YOUR_TOOL_NAME
      restartPolicy: Always
EOF

# Deploy the monitor job
kubectl apply -f monitor-job.yaml
```

### Step 5: Configure Persistent Storage
```bash
# Create directories for persistent data
mkdir -p ~/files-to-be-uploaded
mkdir -p ~/data
mkdir -p ~/uploads-pool

# Update settings.json to use absolute paths
cat > settings.json << EOF
{
  "watch_folder": "/data/project/YOUR_TOOL_NAME/files-to-be-uploaded",
  "processed_files_db": "/data/project/YOUR_TOOL_NAME/data/processed_files.json",
  "app_subtitle": "A tool to batch-upload your freely-licensed photos to Wikimedia Commons",
  "own_work": true,
  "copyright": "CC-BY-SA-4.0",
  "author": "[[User:YourUsername|YourUsername]]",
  "default_categories": [
    "Files uploaded with Folder-to-Commons-Uploader"
  ],
  "source": "{{own}}",
  "enable_duplicate_check": true,
  "check_scaled_variants": true,
  "fuzzy_threshold": 10,
  "block_duplicate_uploads": true,
  "file_ready_min_stable_secs": 1.0,
  "file_ready_max_wait_secs": 6.0,
  "file_ready_poll_interval": 0.5
}
EOF
```

## Accessing Your Tool

Once deployed, your tool will be available at:
```
https://YOUR_TOOL_NAME.toolforge.org/
```

## Useful Commands

### Check Status
```bash
toolforge webservice status
toolforge jobs list
```

### View Logs
```bash
toolforge webservice logs
kubectl logs -l name=YOUR_TOOL_NAME
```

### Restart Service
```bash
toolforge webservice restart
```

### Update Code
```bash
# Pull latest changes
git pull

# Rebuild and redeploy
toolforge build start https://github.com/YOUR_USERNAME/Folder-to-Commons-Uploader.git
toolforge webservice restart
```

## Important Considerations

### Security
- Never commit `.env` file to git (already in .gitignore)
- Use bot passwords, not your main account password
- Restrict file permissions: `chmod 600 .env`

### Storage Limits
- Toolforge provides limited storage per tool
- Monitor your disk usage: `quota`
- Clean up processed files regularly

### Resource Limits
- Web services have memory limits (default: 1GB)
- Consider implementing file size limits
- Add cleanup jobs for old uploaded files

### Commons Authentication
- Register your tool on Meta-Wiki: https://meta.wikimedia.org/wiki/User-Agent_policy
- Use descriptive User-Agent string
- Respect rate limits

## Troubleshooting

### Service Won't Start
```bash
# Check logs
toolforge webservice logs

# Check if ports are in use
netstat -tlnp

# Restart service
toolforge webservice restart
```

### Monitor Not Running
```bash
# Check job status
kubectl get jobs
kubectl get pods

# View logs
kubectl logs -l job-name=folder-monitor
```

### Permission Issues
```bash
# Fix permissions
chmod -R 755 /data/project/YOUR_TOOL_NAME
chmod 600 /data/project/YOUR_TOOL_NAME/.env
```

## Resources

- Toolforge Documentation: https://wikitech.wikimedia.org/wiki/Portal:Toolforge
- Toolforge Help: https://wikitech.wikimedia.org/wiki/Help:Toolforge
- Tool Labs: https://tools.wmflabs.org/
- Commons Bot Policy: https://commons.wikimedia.org/wiki/Commons:Bots

## Support

For Toolforge support:
- IRC: #wikimedia-cloud on Libera.Chat
- Phabricator: https://phabricator.wikimedia.org/ (tag: Toolforge)
- Mailing list: https://lists.wikimedia.org/postorius/lists/cloud.lists.wikimedia.org/
