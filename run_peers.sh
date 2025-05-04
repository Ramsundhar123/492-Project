#!/bin/bash

# Navigate to the base directory that contains 'src'
cd "$(dirname "$0")"

# Compile Java files in FinalProject package inside src
echo "🔧 Compiling FinalProject Java sources from src/..."
cd src || { echo "❌ Cannot find src directory."; exit 1; }
javac FinalProject/*.java || { echo "❌ Compilation failed."; exit 1; }

# Full path to src directory
FULL_PATH=$(pwd)

# Open PeerServer in new Terminal window
osascript <<EOF
tell application "Terminal"
    activate
    do script "cd \"$FULL_PATH\"; echo '🔌 Starting PeerServer...'; java FinalProject.PeerServer"
end tell
EOF

# Wait for server to be ready
sleep 2

# Open PeerClient in new Terminal window
osascript <<EOF
tell application "Terminal"
    activate
    do script "cd \"$FULL_PATH\"; echo '🔗 Starting PeerClient...'; java FinalProject.PeerClient"
end tell
EOF



