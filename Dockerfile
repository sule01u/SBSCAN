FROM python:3.11.6-bullseye

WORKDIR /SBSCAN

COPY requirements.txt .

RUN pip3 install -r requirements.txt

COPY . .

ENTRYPOINT ["python3", "sbscan.py"]
