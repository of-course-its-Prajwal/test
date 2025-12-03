# Use lightweight Python image
FROM python:3.12-slim

# Set working directory inside container
WORKDIR /app

# Copy everything from your project folder
COPY . /app

# Install required Python packages
RUN pip install watchdog cryptography matplotlib

# Expose a display port if GUI is enabled (optional)
ENV DISPLAY=:0

# Default command
CMD ["python3", "fim_gui_v2_full.py"]
