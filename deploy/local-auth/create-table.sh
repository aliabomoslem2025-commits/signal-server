#!/usr/bin/env bash
set -euo pipefail

TABLE_NAME="${LOCAL_AUTH_TABLE:-signal_local_device_auth}"
REGION="${AWS_REGION:-us-east-1}"
ENDPOINT_ARGS=()
if [[ -n "${DYNAMODB_ENDPOINT:-}" ]]; then
  ENDPOINT_ARGS+=(--endpoint-url "$DYNAMODB_ENDPOINT")
fi

aws dynamodb create-table \
  --table-name "$TABLE_NAME" \
  --attribute-definitions AttributeName=PK,AttributeType=S AttributeName=SK,AttributeType=S \
  --key-schema AttributeName=PK,KeyType=HASH AttributeName=SK,KeyType=RANGE \
  --billing-mode PAY_PER_REQUEST \
  --region "$REGION" \
  "${ENDPOINT_ARGS[@]}"

aws dynamodb wait table-exists --table-name "$TABLE_NAME" --region "$REGION" "${ENDPOINT_ARGS[@]}"
printf 'Created local authentication table: %s\n' "$TABLE_NAME"
