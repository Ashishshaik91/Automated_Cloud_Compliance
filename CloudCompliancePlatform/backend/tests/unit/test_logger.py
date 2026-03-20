import logging
import pytest
import structlog

from app.utils.logger import configure_logging

def test_configure_logging_json():
    # Test JSON renderer configuration
    configure_logging(level="DEBUG", fmt="json")
    
    root_logger = logging.getLogger()
    assert root_logger.level == logging.DEBUG
    
    # Check that handlers are attached
    assert len(root_logger.handlers) > 0
    
    # Check structlog is configured
    assert structlog.is_configured()

def test_configure_logging_console():
    # Test Console renderer configuration
    configure_logging(level="INFO", fmt="console")
    
    root_logger = logging.getLogger()
    assert root_logger.level == logging.INFO
    
    uvicorn_logger = logging.getLogger("uvicorn.access")
    assert uvicorn_logger.level == logging.WARNING
