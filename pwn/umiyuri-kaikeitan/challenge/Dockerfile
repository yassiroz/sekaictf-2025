FROM python:3.11

COPY requirements.txt /tmp/requirements.txt

RUN pip install -r /tmp/requirements.txt && \
    rm -f /tmp/requirements.txt

COPY app /app
COPY chall.zip /app

ENV CAPE_BASE_URL=
ENV CAPE_API_KEY=
ENV ANALYSIS_TIMEOUT=
ENV RECAPTCHA_PUBLIC_KEY=
ENV RECAPTCHA_PRIVATE_KEY=
ENV MONGO_URI=
ENV ZIP_TEMPLATE=/app/chall.zip

EXPOSE 8080

CMD ["python", "-u", "/app/app.py"]