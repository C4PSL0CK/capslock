#!/bin/bash
set -e

echo "🚀 Generating OPA Gatekeeper resources from EAPE policies..."

# Build the policy engine
go build -o bin/policy-engine ./cmd/policy-engine

# Create output directory
mkdir -p opa-resources

# Generate OPA resources for each policy
for policy in dev-policy staging-policy prod-policy; do
    echo "Generating OPA resources for: $policy"
    # This will call a new CLI command we'll create
    ./bin/policy-engine convert-opa --policy $policy --output opa-resources/
done

echo "✅ OPA resources generated in opa-resources/"
ls -lh opa-resources/