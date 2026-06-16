"""Utility functions for the version workflow."""

import copy
import os
import re
from datetime import datetime, timezone

from constants import ENV_ATTACK_TREE_TABLE, DEFAULT_REGION, ENV_AWS_REGION
from monitoring import logger, operation_context

REGION = os.environ.get(ENV_AWS_REGION, DEFAULT_REGION)
ATTACK_TREE_TABLE = os.environ.get(ENV_ATTACK_TREE_TABLE)
DEPLOYMENT_MODE = os.environ.get("DEPLOYMENT_MODE", "local").lower()


def _normalize_threat_name(name: str) -> str:
    """Normalize a threat name to match attack_tree_id format."""
    normalized = name.lower().replace(" ", "_")
    normalized = re.sub(r"[^a-zA-Z0-9_\-]", "", normalized)
    return normalized


def _get_db_access():
    """Return database access via factory."""
    if DEPLOYMENT_MODE == "aws":
        import boto3
        return boto3.resource("dynamodb", region_name=REGION)
    else:
        import sys
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))
        from utils.data_access_factory import get_database_access
        return get_database_access(region_name=REGION)


def copy_matching_attack_trees(
    parent_id: str, new_job_id: str, new_threat_list
) -> dict:
    """Copy attack trees from parent that match threats in the new version.

    Args:
        parent_id: job_id of the parent threat model
        new_job_id: job_id of the new threat model
        new_threat_list: ThreatsList of the new version

    Returns:
        dict with copied_count and skipped_count
    """
    if not ATTACK_TREE_TABLE:
        logger.warning("ATTACK_TREE_TABLE not configured, skipping attack tree copy")
        return {"copied_count": 0, "skipped_count": 0}

    with operation_context("copy_attack_trees", new_job_id):
        db = _get_db_access()
        if DEPLOYMENT_MODE == "aws":
            table = db.Table(ATTACK_TREE_TABLE)
        else:
            table = db.table(ATTACK_TREE_TABLE)

        # Get new threat names
        new_threat_names = set()
        if new_threat_list and hasattr(new_threat_list, "threats"):
            for t in new_threat_list.threats:
                new_threat_names.add(t.name)

        if not new_threat_names:
            logger.debug("No threats in new version, skipping attack tree copy")
            return {"copied_count": 0, "skipped_count": 0}

        # Query parent's attack trees using GSI
        parent_trees = []
        if DEPLOYMENT_MODE == "aws":
            query_params = {
                "IndexName": "threat_model_id-index",
                "KeyConditionExpression": "threat_model_id = :tm_id",
                "ExpressionAttributeValues": {":tm_id": parent_id},
            }

            while True:
                response = table.query(**query_params)
                parent_trees.extend(response.get("Items", []))
                last_key = response.get("LastEvaluatedKey")
                if not last_key:
                    break
                query_params["ExclusiveStartKey"] = last_key
        else:
            # Supabase adapter: scan with filter (GSI not needed)
            response = table.scan()
            parent_trees = [
                item for item in response.get("Items", [])
                if item.get("threat_model_id") == parent_id
            ]

        logger.debug(
            "Found parent attack trees",
            parent_id=parent_id,
            tree_count=len(parent_trees),
        )

        copied = 0
        skipped = 0
        current_utc = datetime.now(timezone.utc).isoformat()

        for tree_item in parent_trees:
            threat_name = tree_item.get("threat_name", "")

            # Check if this threat exists in the new version
            if threat_name not in new_threat_names:
                skipped += 1
                continue

            # Create new attack tree item with new IDs
            new_item = copy.deepcopy(tree_item)
            normalized_name = _normalize_threat_name(threat_name)
            new_item["attack_tree_id"] = f"{new_job_id}_{normalized_name}"
            new_item["threat_model_id"] = new_job_id
            new_item["created_at"] = current_utc

            try:
                table.put_item(Item=new_item)
                copied += 1
            except Exception as e:
                logger.error(
                    "Failed to copy attack tree",
                    threat_name=threat_name,
                    error=str(e),
                )
                skipped += 1

        logger.info(
            "Attack tree copy completed",
            new_job_id=new_job_id,
            parent_id=parent_id,
            copied=copied,
            skipped=skipped,
        )

        return {"copied_count": copied, "skipped_count": skipped}
