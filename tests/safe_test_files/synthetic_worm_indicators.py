# Synthetic benign test file for scanner validation only.
# This file is not malware and should not be executed.

import os
import shutil
import socket

# Suspicious indicators intentionally included as text:
# shutil.copy(__file__
# os.walk
# .ssh
# LaunchAgents
# socket.socket
