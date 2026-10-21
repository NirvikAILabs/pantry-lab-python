"""Deletes the database, so the next start has fresh sample data."""
import os

os.remove("pantry.db") if os.path.exists("pantry.db") else None
print("Database reset.")
