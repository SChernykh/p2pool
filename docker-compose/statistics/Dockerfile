FROM python:slim

COPY app /app

WORKDIR /app
RUN pip install -r requirements.txt

CMD ["/app/p2pool_statistics.py"]
