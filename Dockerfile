# Use an official Python base image
FROM python:3.10-slim

# Set environment variables for Python
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

# Install system dependencies required by facenet-pytorch, Pillow, and others
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libgl1 \
    libglib2.0-0 \
    libsm6 \
    libxext6 \
    libxrender-dev \
    && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /app

# Copy requirements first to leverage Docker cache
COPY requirements.txt .

# Install CPU-only PyTorch + other dependencies
RUN pip install --upgrade pip \
    && pip install torch==2.2.2+cpu torchvision==0.17.2+cpu torchaudio==2.2.2+cpu \
       --index-url https://download.pytorch.org/whl/cpu \
    && pip install -r requirements.txt

# Copy application code
COPY . .

# Expose port (Render sets $PORT at runtime)
EXPOSE 8501

# Command to run Streamlit app
CMD ["streamlit", "run", "streamlit_app.py", "--server.port=$PORT", "--server.address=0.0.0.0"]
