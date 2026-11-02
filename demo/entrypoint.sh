#!/bin/sh
# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
# The image carries the listener CA trust chain tlsCa names, from build time.
# Refresh it from the provider at start (a development iya-sts makes a new CA
# when it restarts), unless TLS_CA_REFRESH=0. A failed refresh keeps the file.
if [ "${TLS_CA_REFRESH:-1}" != "0" ]; then
  python3 /app/scripts/trust_chain.py --config "${OIDC_CONFIG:-/app/demo/oidc.json}" || true
fi
exec "$@"
