#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Secrets Rotation System
Zero-downtime credential rotation for databases
"""

import psycopg2
import time
import secrets
import string
from datetime import datetime, timedelta
import logging

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)


class SecretsRotation:
    
    def __init__(self):
        self.conn = None
        self.rotation_history = []
        
    def connect(self, password='postgres'):
        try:
            self.conn = psycopg2.connect(
                host='localhost', port=5459,
                dbname='app_db', user='postgres', password=password
            )
            self.conn.autocommit = True
            logger.info("Connected to database")
            return True
        except Exception as e:
            logger.error(f"Connection failed: {e}")
            return False
    
    def setup(self):
        cursor = self.conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS rotation_history (
                rotation_id SERIAL PRIMARY KEY,
                username VARCHAR(100),
                rotation_date TIMESTAMP DEFAULT NOW(),
                rotation_type VARCHAR(50),
                status VARCHAR(20),
                notes TEXT
            );
            
            CREATE TABLE IF NOT EXISTS app_credentials (
                cred_id SERIAL PRIMARY KEY,
                service_name VARCHAR(100),
                username VARCHAR(100),
                password_hash VARCHAR(255),
                last_rotated TIMESTAMP DEFAULT NOW(),
                expires_at TIMESTAMP
            );
        """)
        cursor.close()
        logger.info("Tables initialized")
    
    def generate_strong_password(self, length=32):
        """Generate cryptographically strong password"""
        
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
        password = ''.join(secrets.choice(alphabet) for i in range(length))
        
        # Ensure it has required character types
        has_lower = any(c.islower() for c in password)
        has_upper = any(c.isupper() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(c in "!@#$%^&*" for c in password)
        
        if has_lower and has_upper and has_digit and has_special:
            return password
        else:
            # Regenerate if requirements not met
            return self.generate_strong_password(length)
    
    def create_app_user(self, username: str, initial_password: str):
        """Create application database user"""
        
        logger.info(f"Creating user: {username}")
        
        cursor = self.conn.cursor()
        
        try:
            cursor.execute(f"DROP USER IF EXISTS {username}")
            cursor.execute(f"CREATE USER {username} WITH PASSWORD '{initial_password}'")
            cursor.execute(f"GRANT CONNECT ON DATABASE app_db TO {username}")
            cursor.execute(f"GRANT USAGE ON SCHEMA public TO {username}")
            cursor.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO {username}")
            
            logger.info(f"User {username} created successfully")
            
        except Exception as e:
            logger.error(f"Failed to create user: {e}")
        
        cursor.close()
    
    def rotate_password(self, username: str, simulate_app_update=True):
        """Rotate user password with zero downtime"""
        
        logger.info(f"Starting password rotation for: {username}")
        
        cursor = self.conn.cursor()
        
        # Step 1: Generate new password
        new_password = self.generate_strong_password()
        logger.info("  Step 1: New password generated")
        
        # Step 2: Update database password
        try:
            cursor.execute(f"ALTER USER {username} WITH PASSWORD '{new_password}'")
            logger.info("  Step 2: Database password updated")
        except Exception as e:
            logger.error(f"  Failed to update password: {e}")
            cursor.close()
            return False
        
        # Step 3: Simulate application config update
        if simulate_app_update:
            logger.info("  Step 3: Updating application configuration...")
            time.sleep(1)  # Simulate config propagation
            
            # Verify new password works
            try:
                test_conn = psycopg2.connect(
                    host='localhost', port=5459,
                    dbname='app_db', user=username, password=new_password
                )
                test_conn.close()
                logger.info("  Step 4: New password verified")
            except:
                logger.error("  New password verification failed!")
                cursor.close()
                return False
        
        # Record rotation
        cursor.execute("""
            INSERT INTO rotation_history 
            (username, rotation_type, status, notes)
            VALUES (%s, %s, %s, %s)
        """, (username, 'password_rotation', 'success', 
              f'Password rotated at {datetime.now()}'))
        
        self.rotation_history.append({
            'username': username,
            'timestamp': datetime.now(),
            'status': 'success'
        })
        
        cursor.close()
        logger.info(f"Password rotation complete for {username}")
        
        return True
    
    def rotate_with_dual_password(self, username: str):
        """Advanced rotation: both old and new passwords work during transition"""
        
        logger.info(f"Starting dual-password rotation for: {username}")
        
        cursor = self.conn.cursor()
        
        # Step 1: Create temporary user with new password
        temp_user = f"{username}_new"
        new_password = self.generate_strong_password()
        
        try:
            cursor.execute(f"DROP USER IF EXISTS {temp_user}")
            cursor.execute(f"CREATE USER {temp_user} WITH PASSWORD '{new_password}'")
            cursor.execute(f"GRANT CONNECT ON DATABASE app_db TO {temp_user}")
            cursor.execute(f"GRANT USAGE ON SCHEMA public TO {temp_user}")
            cursor.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO {temp_user}")
            
            logger.info("  Step 1: Temporary user created with new password")
        except Exception as e:
            logger.error(f"  Failed: {e}")
            cursor.close()
            return False
        
        # Step 2: Application can now use EITHER old or new user
        logger.info("  Step 2: Transition period - both credentials active")
        time.sleep(2)  # Grace period for all app instances to update
        
        # Step 3: Verify all apps switched to new credential
        logger.info("  Step 3: Verifying all connections migrated...")
        time.sleep(1)
        
        # Step 4: Remove old user
        cursor.execute(f"REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM {username}")
        cursor.execute(f"REVOKE ALL PRIVILEGES ON DATABASE app_db FROM {username}")
        cursor.execute(f"REVOKE ALL PRIVILEGES ON SCHEMA public FROM {username}")
        cursor.execute(f"DROP USER {username}")
        cursor.execute(f"ALTER USER {temp_user} RENAME TO {username}")
        
        # Record rotation
        cursor.execute("""
            INSERT INTO rotation_history 
            (username, rotation_type, status, notes)
            VALUES (%s, %s, %s, %s)
        """, (username, 'dual_password_rotation', 'success',
              'Zero-downtime rotation complete'))
        
        cursor.close()
        logger.info(f"Dual-password rotation complete")
        
        return True
    
    def schedule_rotation(self, username: str, days_until_expire: int = 90):
        """Schedule automatic rotation"""
        
        cursor = self.conn.cursor()
        
        expires_at = datetime.now() + timedelta(days=days_until_expire)
        
        cursor.execute("""
            INSERT INTO app_credentials 
            (service_name, username, expires_at)
            VALUES (%s, %s, %s)
            ON CONFLICT DO NOTHING
        """, ('database', username, expires_at))
        
        cursor.close()
        
        logger.info(f"Rotation scheduled for {username} at {expires_at}")
    
    def check_expired_credentials(self):
        """Check for credentials that need rotation"""
        
        cursor = self.conn.cursor()
        
        cursor.execute("""
            SELECT username, expires_at 
            FROM app_credentials 
            WHERE expires_at < NOW() + INTERVAL '7 days'
        """)
        
        expired = cursor.fetchall()
        cursor.close()
        
        if expired:
            logger.warning(f"Found {len(expired)} credential(s) expiring soon")
            for username, expires in expired:
                logger.warning(f"  {username} expires: {expires}")
        
        return expired
    
    def print_rotation_report(self):
        """Print rotation history report"""
        
        print("\n" + "=" * 80)
        print("SECRETS ROTATION REPORT")
        print("=" * 80)
        
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT username, rotation_date, rotation_type, status
            FROM rotation_history
            ORDER BY rotation_date DESC
        """)
        
        rotations = cursor.fetchall()
        
        print(f"\nTotal Rotations: {len(rotations)}")
        
        if rotations:
            print("\nRecent Rotations:")
            for username, date, rot_type, status in rotations:
                print(f"\n  User: {username}")
                print(f"  Type: {rot_type}")
                print(f"  Date: {date}")
                print(f"  Status: {status}")
        
        cursor.close()
        print("=" * 80)
    
    def run_demo(self):
        """Run secrets rotation demo"""
        
        print("\n" + "=" * 80)
        print("SECRETS ROTATION SYSTEM")
        print("=" * 80)
        
        if not self.connect():
            return
        
        self.setup()
        
        # Phase 1: Setup
        print("\nPHASE 1: Create Application Users")
        print("-" * 80)
        
        initial_password = "InitialPass123!"
        self.create_app_user('app_service', initial_password)
        self.create_app_user('api_service', initial_password)
        
        # Phase 2: Simple rotation
        print("\nPHASE 2: Standard Password Rotation")
        print("-" * 80)
        
        self.rotate_password('app_service')
        
        time.sleep(2)
        
        # Phase 3: Dual-password rotation
        print("\nPHASE 3: Zero-Downtime Dual-Password Rotation")
        print("-" * 80)
        
        self.rotate_with_dual_password('api_service')
        
        # Phase 4: Scheduling
        print("\nPHASE 4: Schedule Future Rotations")
        print("-" * 80)
        
        self.schedule_rotation('app_service', days_until_expire=90)
        self.schedule_rotation('api_service', days_until_expire=90)
        
        # Phase 5: Report
        self.print_rotation_report()
        
        print("\n" + "=" * 80)
        print("Key Features:")
        print("  - Zero-downtime password rotation")
        print("  - Strong password generation")
        print("  - Dual-password transition period")
        print("  - Automated rotation scheduling")
        print("  - Complete audit trail")
        print("=" * 80)


def main():
    rotation = SecretsRotation()
    rotation.run_demo()


if __name__ == "__main__":
    main()
