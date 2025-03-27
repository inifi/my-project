#!/usr/bin/env python
"""
Database Rebuilding Tool

This script rebuilds the database from scratch without attempting to preserve data.
Use this when you need a fresh start or when the database is irreparably corrupted.
"""

import os
import sys
import sqlite3
import logging
from datetime import datetime
import config

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def ensure_instance_directory():
    """Ensure the instance directory exists"""
    instance_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'instance')
    if not os.path.exists(instance_dir):
        os.makedirs(instance_dir)
        logger.info(f"Created instance directory at {instance_dir}")
    return instance_dir

def get_db_path():
    """Get the database path"""
    # Get the instance directory
    instance_dir = ensure_instance_directory()
    
    # Return the path to the database file
    db_path = os.path.join(instance_dir, 'ai_system.db')
    logger.info(f"Database path: {db_path}")
    return db_path

def create_empty_database(db_path):
    """Create an empty database"""
    # Delete the database file if it exists
    if os.path.exists(db_path):
        logger.info(f"Removing existing database at {db_path}")
        os.remove(db_path)
    
    # Create an empty database file
    conn = sqlite3.connect(db_path)
    conn.close()
    logger.info(f"Created empty database at {db_path}")
    return True

def main():
    """Main function to rebuild the database"""
    logger.info("Starting database rebuild")
    
    try:
        # Get the database path
        db_path = get_db_path()
        
        # Create an empty database
        if create_empty_database(db_path):
            logger.info("Database rebuild successful")
            return True
        else:
            logger.error("Failed to rebuild database")
            return False
    except Exception as e:
        logger.error(f"Error rebuilding database: {str(e)}")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)