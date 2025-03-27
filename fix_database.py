#!/usr/bin/env python
"""
Database Schema Fix Tool

This script fixes database schema issues by directly modifying the SQLite database
structure without requiring a complete rebuild. It uses low-level SQLite operations
to add missing columns while preserving existing data.
"""

import os
import sys
import sqlite3
import logging
import time
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Import bypass system for advanced capabilities
try:
    from utils.advanced_bypass import bypass_system
    BYPASS_AVAILABLE = True
except ImportError:
    BYPASS_AVAILABLE = False

def get_db_path():
    """Get the database path from configuration"""
    from app import app
    db_uri = app.config['SQLALCHEMY_DATABASE_URI'].replace('sqlite:///', '')
    
    # Check if path is relative or absolute
    if db_uri.startswith('/'):
        return db_uri
    else:
        # Check for instance folder
        instance_path = os.path.join('instance', db_uri)
        if os.path.exists(instance_path):
            return instance_path
        # Check in current directory
        elif os.path.exists(db_uri):
            return db_uri
        else:
            # Still not found, try some common locations
            common_paths = [
                os.path.join('instance', 'ai_system.db'),
                'ai_system.db',
                os.path.join('instance', 'site.db'),
                'site.db'
            ]
            
            for path in common_paths:
                if os.path.exists(path):
                    logger.info(f"Found database at {path}")
                    return path
            
            logger.error("Could not find database file")
            return db_uri

def backup_database(db_path):
    """Create a backup of the database before modifications"""
    import shutil
    backup_path = f"{db_path}.backup_{int(time.time())}"
    shutil.copy2(db_path, backup_path)
    logger.info(f"Database backup created at {backup_path}")
    return backup_path

def check_column_exists(conn, table, column):
    """Check if a column exists in a table"""
    cursor = conn.cursor()
    cursor.execute(f"PRAGMA table_info({table})")
    columns = cursor.fetchall()
    for col in columns:
        if col[1] == column:
            return True
    return False

def add_column(conn, table, column, column_type, default_value=None):
    """Add a column to a table"""
    cursor = conn.cursor()
    
    # Check if column already exists
    if check_column_exists(conn, table, column):
        logger.info(f"Column {column} already exists in table {table}")
        return False
        
    # Add the column
    sql = f"ALTER TABLE {table} ADD COLUMN {column} {column_type}"
    
    if default_value is not None:
        if isinstance(default_value, str):
            sql += f" DEFAULT '{default_value}'"
        else:
            sql += f" DEFAULT {default_value}"
    
    try:
        cursor.execute(sql)
        conn.commit()
        logger.info(f"Added column {column} to table {table}")
        return True
    except sqlite3.Error as e:
        logger.error(f"Error adding column {column} to table {table}: {str(e)}")
        return False

def fix_learning_sources_table(conn):
    """Fix the learning_sources table by adding missing columns"""
    # Add the priority column with default value 'normal'
    success1 = add_column(conn, 'learning_sources', 'priority', 'VARCHAR(16)', 'normal')
    
    # Add the source_metadata column
    success2 = add_column(conn, 'learning_sources', 'source_metadata', 'TEXT', '{}')
    
    if success1:
        # Update values based on source_type for better prioritization
        cursor = conn.cursor()
        cursor.execute("UPDATE learning_sources SET priority = 'high' WHERE source_type IN ('research', 'api')")
        cursor.execute("UPDATE learning_sources SET priority = 'highest' WHERE source_type = 'owner_input'")
        conn.commit()
        logger.info("Updated priority values based on source types")
    
    if success2:
        logger.info("Added source_metadata column to learning_sources table")
    
    return success1 or success2

def create_backup_tables(conn):
    """Create backup tables for recovery purposes"""
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = cursor.fetchall()
    
    for table in tables:
        table_name = table[0]
        if table_name.startswith('sqlite_'):
            continue
            
        backup_table = f"{table_name}_backup"
        
        try:
            cursor.execute(f"DROP TABLE IF EXISTS {backup_table}")
            cursor.execute(f"CREATE TABLE {backup_table} AS SELECT * FROM {table_name}")
            logger.info(f"Created backup table {backup_table}")
        except sqlite3.Error as e:
            logger.error(f"Error creating backup table for {table_name}: {str(e)}")
    
    conn.commit()

def verify_database_integrity(conn):
    """Verify the integrity of the database"""
    cursor = conn.cursor()
    
    try:
        cursor.execute("PRAGMA integrity_check")
        result = cursor.fetchone()[0]
        
        if result != "ok":
            logger.error(f"Database integrity check failed: {result}")
            return False
            
        logger.info("Database integrity check passed")
        return True
    except sqlite3.Error as e:
        logger.error(f"Error checking database integrity: {str(e)}")
        return False

def optimize_database(conn):
    """Optimize the database after modifications"""
    cursor = conn.cursor()
    
    try:
        # Set optimized pragmas
        optimizations = [
            "PRAGMA journal_mode = WAL",
            "PRAGMA synchronous = NORMAL",
            "PRAGMA temp_store = MEMORY",
            "PRAGMA mmap_size = 30000000",
            "VACUUM",
            "ANALYZE"
        ]
        
        for opt in optimizations:
            cursor.execute(opt)
            
        conn.commit()
        logger.info("Database optimized successfully")
        return True
    except sqlite3.Error as e:
        logger.error(f"Error optimizing database: {str(e)}")
        return False

def add_recovery_data():
    """Add recovery data using bypass system if available"""
    if not BYPASS_AVAILABLE:
        return
        
    # Store recovery information in bypass system
    try:
        db_path = get_db_path()
        recovery_data = {
            "db_path": db_path,
            "timestamp": str(datetime.now()),
            "schema_version": 2,  # Increment this when schema changes
            "columns_added": ["learning_sources.priority"]
        }
        
        bypass_system.store_persistent_data("db_recovery_info", str(recovery_data))
        logger.info("Stored recovery information in bypass system")
    except Exception as e:
        logger.error(f"Error storing recovery data: {str(e)}")

def main():
    """Main function to fix the database"""
    logger.info("Starting database schema fix")
    
    try:
        # Get database path
        db_path = get_db_path()
        
        if not os.path.exists(db_path):
            logger.error(f"Database file not found at {db_path}")
            return False
            
        # Create a backup
        backup_path = backup_database(db_path)
        
        # Connect to the database
        conn = sqlite3.connect(db_path)
        
        # Create backup tables
        create_backup_tables(conn)
        
        # Fix learning_sources table
        success = fix_learning_sources_table(conn)
        
        if success:
            # Verify database integrity
            if verify_database_integrity(conn):
                # Optimize database
                optimize_database(conn)
                
                # Add recovery data
                add_recovery_data()
                
                logger.info("Database schema fix completed successfully")
                return True
            else:
                logger.error("Database integrity check failed after modifications")
                return False
        else:
            logger.error("Failed to fix learning_sources table")
            return False
    except Exception as e:
        logger.error(f"Error fixing database schema: {str(e)}")
        return False
    finally:
        if 'conn' in locals():
            conn.close()

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)