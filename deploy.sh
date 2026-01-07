#!/bin/bash
echo "🚀 Deploying Witcher Crystal Ball..."
echo "📤 Uploading files to server..."
scp -r . root@65.109.164.22:/opt/witcher-crystal-ball/

echo "🔄 Restarting bot service..."
ssh root@65.109.164.22 "cd /opt/witcher-crystal-ball && sudo systemctl restart witcher-bot"

echo "✅ Deployment complete!"
echo "📊 Check status with: ssh root@65.109.164.22 'sudo systemctl status witcher-bot'"
