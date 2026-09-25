"""Phase 1.6 -- disaster-recovery package: MySQL + object-storage backup, restore,
verification, retention/cleanup, metrics, and structured logging.

Pure-Python around injectable seams (MySQLRunner for mysqldump/mysql, ObjectStore for
S3/MinIO) so the full flow is unit-testable without external binaries or a live MinIO.
The application, schema, and security config are never modified -- this only reads/writes
the database and object storage.
"""
