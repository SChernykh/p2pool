FROM python:3.10.5-bullseye

WORKDIR /app

ADD requirements.txt /app/
RUN /usr/local/bin/pip3 install -r requirements.txt

ADD configure.py /app/
ADD defaults /app/
ADD current_config.jinja2 /app/
ADD docker-compose.jinja2 /app/

ENTRYPOINT ["/usr/local/bin/python3"]
CMD ["/app/configure.py"]
