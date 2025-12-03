
# 🚀 FIM Tool - Docker Instructions

This tool is designed to run as a container with a GUI-based dashboard for File Integrity Monitoring.

---

## 🐳 Pull the Docker Image

```bash
docker pull praz09/fim-tool:latest
```

---

## ▶️ Run the Container (with GUI support)

If using Linux with X11:

```bash
xhost +local:docker  # Allow Docker to access your display
docker run -it \
    --env DISPLAY=$DISPLAY \
    --volume /tmp/.X11-unix:/tmp/.X11-unix \
    praz09/fim-tool

```

---

## ⚠️ Notes:
- **Only tested on Linux (Ubuntu/Linux Mint)** with a GUI environment.
- Python dependencies and scripts are already included inside the image.
- You can monitor any directory from the GUI.
- Logs and certs are stored inside the container unless volume mounted externally.

---

## 📁 Optional: Save Logs or Certificates Outside

To store the logs or certs outside the container:

```bash
docker run -it \
    --env DISPLAY=$DISPLAY \
    --volume /tmp/.X11-unix:/tmp/.X11-unix \
    --volume ~/fim_logs:/fim_pki_tool/logs \
    praz09/fim-tool

```
