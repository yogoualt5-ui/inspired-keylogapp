FROM python:3.11-slim

WORKDIR /box
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app

EXPOSE 5000
CMD ["python", "app/app.py"]
