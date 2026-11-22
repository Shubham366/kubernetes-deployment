# Linux provisioning backend: Python stdlib app + ansible-core + ssh client.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    HOME=/home/provisioner \
    ANSIBLE_LOCAL_TEMP=/tmp/ansible \
    ANSIBLE_REMOTE_TEMP=/tmp/.ansible-remote \
    PROVISIONER_DATA_DIR=/data \
    PROVISIONER_API_HOST=0.0.0.0 \
    PROVISIONER_API_PORT=8080

RUN apt-get update \
 && apt-get install -y --no-install-recommends openssh-client sshpass ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd -g 10001 provisioner \
 && useradd -u 10001 -g 10001 -d /home/provisioner -m -s /usr/sbin/nologin provisioner \
 && mkdir -p /data /app /tmp/ansible \
 && chown -R provisioner:provisioner /data /app /tmp/ansible

WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir "ansible-core>=2.15,<2.19"

COPY --chown=provisioner:provisioner main.py ./
COPY --chown=provisioner:provisioner provisioner ./provisioner
COPY --chown=provisioner:provisioner ansible ./ansible
COPY --chown=provisioner:provisioner examples ./examples

USER 10001:10001
VOLUME ["/data"]
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/api/v1/health', timeout=2).status==200 else 1)"

ENTRYPOINT ["python", "main.py"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8080"]
