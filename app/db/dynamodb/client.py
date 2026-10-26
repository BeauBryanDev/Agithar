from functools import lru_cache

import boto3
from botocore.config import Config

from app.core.config import get_settings

BOTO_CONFIG = Config(
    connect_timeout=3,
    read_timeout=5,
    retries={"max_attempts": 3, "mode": "standard"},
)
EXPECTED_KEYS = {"PK": "HASH", "SK": "RANGE"}
EXPECTED_INDEX_KEYS = {"GSI1PK": "HASH", "GSI1SK": "RANGE"}
INDEX_NAME = "GSI1"


class TableSchemaError(Exception):
    pass


@lru_cache(maxsize=1)
def get_dynamodb_table():
    # Credentials come from the instance role (IMDSv2), never from code.
    settings = get_settings()
    resource = boto3.resource(
        "dynamodb",
        region_name=settings.aws_region,
        config=BOTO_CONFIG,
    )

    return resource.Table(settings.dynamodb_chat_table)


def key_map(schema: list[dict]) -> dict[str, str]:
    keys = {}

    for entry in schema:
        keys[entry["AttributeName"]] = entry["KeyType"]

    return keys


def check_table_schema(table) -> None:
    # Fails closed when the table keys differ from what the code writes.
    description = table.meta.client.describe_table(TableName=table.name)
    found = description["Table"]

    if key_map(found["KeySchema"]) != EXPECTED_KEYS:
        raise TableSchemaError(f"table keys are {key_map(found['KeySchema'])}")

    for index in found.get("GlobalSecondaryIndexes", []):
        if index["IndexName"] == INDEX_NAME:
            if key_map(index["KeySchema"]) != EXPECTED_INDEX_KEYS:
                raise TableSchemaError("GSI1 keys differ")

            return

    raise TableSchemaError("GSI1 index is missing")
