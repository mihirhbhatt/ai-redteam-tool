FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

RUN groupadd --system --gid 10001 redteam \
    && useradd --system --uid 10001 --gid redteam --home-dir /app redteam
COPY --chown=redteam:redteam . .

RUN mkdir -p logs reports/output data/results \
    && chown -R redteam:redteam logs reports/output data/results

USER redteam

ENTRYPOINT ["python", "main.py"]
CMD ["--config", "config/config.yaml"]