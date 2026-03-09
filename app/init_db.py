import logging

from app.database import init_db

logger = logging.getLogger(__name__)


if __name__ == "__main__":
    # Standalone helper entrypoint for local schema initialization.
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s [%(name)s] %(message)s")
    logger.info("Manual database initialization started")
    init_db()
    logger.info("Manual database initialization completed")
