FROM python:3.13-slim

WORKDIR /app
COPY . /app
RUN pip install -r requirements.txt

EXPOSE 22
EXPOSE 8000

CMD ["python", "-m", "http.server", "8000"]
