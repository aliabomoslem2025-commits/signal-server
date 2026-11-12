#!/usr/bin/env bash
set -euo pipefail

TABLE_NAME="${LOCAL_AUTH_TABLE:-signal_local_device_auth}"
REGION="${AWS_REGION:-us-east-1}"
ENDPOINT_ARGS=()
if [[ -n "${DYNAMODB_ENDPOINT:-}" ]]; then
  ENDPOINT_ARGS+=(--endpoint-url "$DYNAMODB_ENDPOINT")
fi

if ! aws dynamodb describe-table --table-name "$TABLE_NAME" --region "$REGION" "${ENDPOINT_ARGS[@]}" >/dev/null 2>&1; then
  aws dynamodb create-table \
    --table-name "$TABLE_NAME" \
    --attribute-definitions AttributeName=PK,AttributeType=S AttributeName=SK,AttributeType=S \
    --key-schema AttributeName=PK,KeyType=HASH AttributeName=SK,KeyType=RANGE \
    --billing-mode PAY_PER_REQUEST \
    --region "$REGION" \
    "${ENDPOINT_ARGS[@]}"
fi

aws dynamodb wait table-exists --table-name "$TABLE_NAME" --region "$REGION" "${ENDPOINT_ARGS[@]}"

TTL_STATUS="$(aws dynamodb describe-time-to-live --table-name "$TABLE_NAME" --region "$REGION" "${ENDPOINT_ARGS[@]}" --query 'TimeToLiveDescription.TimeToLiveStatus' --output text 2>/dev/null || true)"
if [[ "$TTL_STATUS" == "DISABLED" || "$TTL_STATUS" == "None" || -z "$TTL_STATUS" ]]; then
  aws dynamodb update-time-to-live \
    --table-name "$TABLE_NAME" \
    --time-to-live-specification Enabled=true,AttributeName=expiresAt \
    --region "$REGION" \
    "${ENDPOINT_ARGS[@]}"
fi

printf 'Local authentication table is ready: %s (TTL attribute: expiresAt)\n' "$TABLE_NAME"
