"""
BRAMKA AI - Logging System
Professional logging with rotation, colors, and multiple outputs
"""
import sys
from pathlib import Path
from loguru import logger
from typing import Optional
def setup_logger(
    log_level: str = "INFO",
    log_file: Optional[str] = None,
    rotation: str = "10 MB",
    retention: str = "1 week",
    colorize: bool = True
):
    """
    Setup centralized logging for BRAMKA AI

    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Path to log file (optional)
        rotation: When to rotate log file
        retention: How long to keep old logs
        colorize: Use colored output
    """
    # Remove default handler
    logger.remove()

    # Console handler with colors
    logger.add(
        sys.stderr,
        format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - <level>{message}</level>",
        level=log_level,
        colorize=colorize
    )

    # File handler (if specified)
    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)

        logger.add(
            log_file,
            format="{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {name}:{function}:{line} - {message}",
            level=log_level,
            rotation=rotation,
            retention=retention,
            compression="zip"
        )

    logger.info(f"Logger initialized - Level: {log_level}")

    return logger
def get_logger(name: str):
    """
    Get logger instance for a module

    Args:
        name: Module name (usually __name__)

    Returns:
        Logger instance
    """
    return logger.bind(name=name)
