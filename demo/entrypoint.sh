#!/bin/sh
# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
# Refresh the listener CA trust chain named by tlsCa, then start the demo.
python3 /app/scripts/trust_chain.py --config "${OIDC_CONFIG:-/app/demo/oidc.json}" || true
exec "$@"
