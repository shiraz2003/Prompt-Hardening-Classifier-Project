FROM python:3.11-slim

ENV PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8000 7860

# Default: run the FastAPI service. Override CMD to launch the Gradio demo.
CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000"]
