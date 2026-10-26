from typing import Any

from boto3.dynamodb.conditions import Key

META_SORT_KEY = "META"
MESSAGE_PREFIX = "MSG#"
INDEX_NAME = "GSI1"
USER_ROLES = ("admin", "operator")
MAX_PAGES = 20


class NotRegisteredUserError(ValueError):
    pass


def conversation_pk(conversation_id: str) -> str:
    return f"CONV#{conversation_id}"


def user_pk(user_id: int) -> str:
    return f"USER#{user_id}"


def meta_key(conversation_id: str) -> dict[str, str]:
    return {
        "PK": conversation_pk(conversation_id),
        "SK": META_SORT_KEY,
    }


def check_user(user_id: int, user_role: str | None = None) -> None:
    # Only registered users (a database id and a known role) are stored.
    if isinstance(user_id, bool) or not isinstance(user_id, int):
        raise NotRegisteredUserError("user id must be an integer")

    if user_id <= 0:
        raise NotRegisteredUserError("user id must be positive")

    if user_role is not None and user_role not in USER_ROLES:
        raise NotRegisteredUserError("unknown user role")


def query_all(table, limit: int, **kwargs: Any) -> list[dict[str, Any]]:
    # A query returns at most 1 MB per call, so follow the pages.
    items: list[dict[str, Any]] = []
    pages = 0

    while len(items) < limit and pages < MAX_PAGES:
        response = table.query(Limit=limit - len(items), **kwargs)
        items.extend(response.get("Items", []))
        pages += 1
        last_key = response.get("LastEvaluatedKey")

        if last_key is None:
            break

        kwargs["ExclusiveStartKey"] = last_key

    return items[:limit]


def get_conversation(table, conversation_id: str) -> dict[str, Any] | None:
    response = table.get_item(
        Key=meta_key(conversation_id),
        ConsistentRead=True,
    )

    return response.get("Item")


def create_conversation(
    table,
    conversation_id: str,
    user_id: int,
    user_role: str,
    title: str,
    started_at: str,
    expires_at: int,
) -> None:
    check_user(user_id, user_role)
    item = {
        **meta_key(conversation_id),
        "conversation_id": conversation_id,
        "user_id": user_id,
        "user_role": user_role,
        "title": title,
        "started_at": started_at,
        "last_message_at": started_at,
        "message_count": 0,
        "GSI1PK": user_pk(user_id),
        "GSI1SK": f"{started_at}#{conversation_id}",
        "expires_at": expires_at,
    }
    table.put_item(
        Item=item,
        ConditionExpression="attribute_not_exists(PK)",
    )


def message_item(
    conversation_id: str,
    user_id: int,
    index: int,
    message: dict[str, Any],
    expires_at: int,
) -> dict[str, Any]:
    # The index keeps the analyst message before the reply of one turn.
    created_at = message["created_at"]
    item = {
        "PK": conversation_pk(conversation_id),
        "SK": f"{MESSAGE_PREFIX}{created_at}#{index}#{message['message_id']}",
        "conversation_id": conversation_id,
        "user_id": user_id,
        "expires_at": expires_at,
    }
    item.update(message)

    return item


def save_turn(
    table,
    conversation_id: str,
    user_id: int,
    messages: list[dict[str, Any]],
    last_message_at: str,
    expires_at: int,
) -> None:
    # One transaction: the messages and the conversation counters, and only
    # if the conversation still exists and belongs to this user.
    check_user(user_id)
    actions: list[dict[str, Any]] = []

    for index, message in enumerate(messages):
        item = message_item(
            conversation_id, user_id, index, message, expires_at
        )
        actions.append({"Put": {"TableName": table.name, "Item": item}})

    actions.append({
        "Update": {
            "TableName": table.name,
            "Key": meta_key(conversation_id),
            "UpdateExpression": (
                "SET last_message_at = :now, GSI1SK = :gsi1sk, "
                "expires_at = :expires ADD message_count :count"
            ),
            "ConditionExpression": "user_id = :user_id",
            "ExpressionAttributeValues": {
                ":now": last_message_at,
                ":gsi1sk": f"{last_message_at}#{conversation_id}",
                ":expires": expires_at,
                ":count": len(messages),
                ":user_id": user_id,
            },
        }
    })
    table.meta.client.transact_write_items(TransactItems=actions)


def list_conversations(
    table, user_id: int, limit: int
) -> list[dict[str, Any]]:
    check_user(user_id)

    return query_all(
        table,
        limit,
        IndexName=INDEX_NAME,
        KeyConditionExpression=Key("GSI1PK").eq(user_pk(user_id)),
        ScanIndexForward=False,
    )


def list_messages(
    table, conversation_id: str, limit: int
) -> list[dict[str, Any]]:
    # The newest messages, returned oldest first.
    items = query_all(
        table,
        limit,
        KeyConditionExpression=(
            Key("PK").eq(conversation_pk(conversation_id))
            & Key("SK").begins_with(MESSAGE_PREFIX)
        ),
        ScanIndexForward=False,
    )
    items.reverse()

    return items


def delete_conversation(table, conversation_id: str) -> int:
    keys = query_all(
        table,
        100_000,
        KeyConditionExpression=Key("PK").eq(conversation_pk(conversation_id)),
        ProjectionExpression="PK, SK",
    )

    with table.batch_writer() as batch:
        for key in keys:
            batch.delete_item(Key={"PK": key["PK"], "SK": key["SK"]})

    return len(keys)
