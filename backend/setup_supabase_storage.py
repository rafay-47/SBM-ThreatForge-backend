"""Create Supabase storage buckets if they don't exist.

Run once before starting the backend to ensure the required
Supabase storage buckets are provisioned.
"""

import json
import os
import sys
from urllib import request, error

def load_env():
    """Load .env file if present."""
    try:
        from dotenv import load_dotenv
        load_dotenv(os.path.join(os.path.dirname(__file__), "..", ".env"), override=True)
    except ImportError:
        pass

def main():
    load_env()

    supabase_url = os.getenv("SUPABASE_URL", "").rstrip("/")
    service_role_key = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "")

    if not supabase_url or not service_role_key:
        print("ERROR: SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY must be set in .env")
        sys.exit(1)

    buckets = ["architecture-bucket", "spaces-bucket"]
    headers = {
        "apikey": service_role_key,
        "Authorization": f"Bearer {service_role_key}",
        "Content-Type": "application/json",
    }

    for bucket in buckets:
        # Check if bucket exists
        try:
            req = request.Request(
                f"{supabase_url}/storage/v1/bucket/{bucket}",
                headers=headers,
            )
            with request.urlopen(req, timeout=10) as resp:
                print(f"Bucket '{bucket}' already exists")
                continue
        except error.HTTPError as e:
            if e.code != 404:
                print(f"Error checking bucket '{bucket}': {e.code} {e.read().decode()}")
                continue
            # 404 means bucket doesn't exist, create it

        # Create bucket
        try:
            data = json.dumps({"id": bucket, "name": bucket, "public": False}).encode()
            req = request.Request(
                f"{supabase_url}/storage/v1/bucket",
                data=data,
                headers=headers,
                method="POST",
            )
            with request.urlopen(req, timeout=10) as resp:
                print(f"Created bucket '{bucket}'")
        except error.HTTPError as e:
            detail = e.read().decode()
            if "already exists" in detail.lower():
                print(f"Bucket '{bucket}' already exists (race)")
            else:
                print(f"Error creating bucket '{bucket}': {e.code} {detail}")

    print("Done.")

if __name__ == "__main__":
    main()
