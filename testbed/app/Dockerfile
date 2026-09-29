FROM python:3.11-slim
RUN pip install --no-cache-dir flask gunicorn
WORKDIR /app
COPY app.py . 
CMD ["gunicorn", "-b", "0.0.0.0:5000", "app:app"]