FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app
COPY server/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && useradd --system --uid 10001 --create-home fleetview
COPY server/app ./app
COPY agent /opt/fleetview-install/source/agent
COPY scripts/uninstall-agent.sh /opt/fleetview-install/source/scripts/uninstall-agent.sh
COPY scripts/install-agent.ps1 /opt/fleetview-install/source/scripts/install-agent.ps1
COPY scripts/uninstall-agent.ps1 /opt/fleetview-install/source/scripts/uninstall-agent.ps1
COPY scripts/remote-install-linux.sh /opt/fleetview-install/install-linux.sh
RUN python -c "import tarfile; t=tarfile.open('/opt/fleetview-install/agent-source.tar.gz','w:gz'); t.add('/opt/fleetview-install/source/agent',arcname='agent'); t.add('/opt/fleetview-install/source/scripts',arcname='scripts'); t.close()" \
    && chmod 0644 /opt/fleetview-install/agent-source.tar.gz /opt/fleetview-install/install-linux.sh
USER fleetview
EXPOSE 8080
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080", "--proxy-headers", "--forwarded-allow-ips", "127.0.0.1"]
