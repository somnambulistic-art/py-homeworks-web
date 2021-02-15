FROM python:3.8

COPY ./flask /flask-app

RUN pip install -r flask-app/requirements.txt

CMD ["python", "flask-app/app.py"]