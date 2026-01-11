import logging
import os
import json
from logging.handlers import HTTPHandler


class JSONFormatter(logging.Formatter):
    def format(self, record):
        payload = {
            "timestamp": self.formatTime(record),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            payload['exc_info'] = self.formatException(record.exc_info)
        return json.dumps(payload)


def configure_json_logging(siem_endpoint: str | None = None, level=logging.INFO):
    logger = logging.getLogger()
    logger.setLevel(level)

    handler = logging.StreamHandler()
    handler.setFormatter(JSONFormatter())
    logger.addHandler(handler)

    if siem_endpoint:
        # siem_endpoint format: host:port
        host, port = siem_endpoint.split(':')
        http = HTTPHandler(host, '/ingest', method='POST')
        http.setFormatter(JSONFormatter())
        logger.addHandler(http)

    return logger
