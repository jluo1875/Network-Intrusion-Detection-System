FROM python:3.8

COPY ./src/requirements.txt .
RUN python3 -m pip install -r requirements.txt

COPY ./src /app/

RUN chmod +rx /app/main.py

RUN which python3

CMD ["python3","-m","/app/main.py"]

ENTRYPOINT [ "/app/main.py" ]
