FROM python:3.8-slim

WORKDIR /smartmeter

COPY requirements.txt .

RUN pip install -r requirements.txt

COPY meter_reading.py .

ENTRYPOINT [ "python", "./meter_reading.py" ]

