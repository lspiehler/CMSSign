#!/bin/bash
# CMSSign tests: builds CMSSign, makes a throwaway RSA 2048 RA certificate (pkiaas always makes SCEP RA keys
# RSA 2048) and checks SCEP CertRep responses the way pkiaas calls CMSSign (lib/scep/PKIOperation.js):
#   success: <pfx> <password|stdin> <content> <senderNonce> <recipientNonce> <transactionID> <out> <digest>
#   failure: <pfx> <password|stdin> <content> <senderNonce> <recipientNonce> <transactionID> <out> <pkiStatus> <failInfo> <failInfoText> <digest>
# Needs the .NET 10 SDK and OpenSSL 3. Prints PASS/FAIL for each check and exits 1 if any check fails.
set -u
REPO="$(cd "$(dirname "$0")/.." && pwd)"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

PASSED=0
FAILED=0
pass() { echo "PASS  $1"; PASSED=$((PASSED+1)); }
fail() { echo "FAIL  $1${2:+ ($2)}"; FAILED=$((FAILED+1)); }
check() { if [ "$2" = "$3" ]; then pass "$1"; else fail "$1" "got '$2', expected '$3'"; fi; }

if ! dotnet build "$REPO/CMSSign/CMSSign.csproj" -c Release -o "$WORK/build" > "$WORK/build.log" 2>&1; then
    cat "$WORK/build.log"
    echo "FAIL  build"
    exit 1
fi
CMSSIGN="$WORK/build/CMSSign.dll"
cd "$WORK"

PASSWORD="test pass $RANDOM"
SENDERNONCE=0123456789ABCDEF0123456789ABCDEF
RECIPIENTNONCE=FEDCBA9876543210FEDCBA9876543210
TRANSID="test-transaction-$RANDOM"
openssl req -x509 -newkey rsa:2048 -nodes -keyout ra.key -out ra.crt -subj "/CN=CMSSign test RA" -days 1 -addext keyUsage=critical,digitalSignature 2>/dev/null
openssl pkcs12 -export -inkey ra.key -in ra.crt -out ra.pfx -passout "pass:$PASSWORD"
RA_FINGERPRINT=$(openssl x509 -in ra.crt -noout -fingerprint -sha256)
# the same content pkiaas signs: a degenerate PKCS#7 with the issued certificate, or an empty OCTET STRING for a failure
openssl crl2pkcs7 -nocrl -certfile ra.crt -outform DER -out cert.p7b
openssl asn1parse -genstr FORMAT:HEX,OCTETSTRING:00 -out empty.asn1 >/dev/null

# attr <response> <oid>: the printed value of a signed attribute, e.g. PRINTABLESTRING:3, or the hex of an OCTET STRING
attr() {
    local value
    value=$(openssl cms -cmsout -print -inform DER -in "$1" | awk -v oid="($2)" '
        /^ *object: / { inattr = (index($0, oid) > 0); next }
        inattr && /^ *(set|signatureAlgorithm|unsignedAttrs):/ { if ($1 != "set:") exit; next }
        inattr && /^ *$/ { exit }
        inattr { sub(/^ */, ""); print }')
    if [ "${value%%$'\n'*}" = "OCTET STRING:" ]; then
        # hex dump lines: "0000 - 01 23 45 67 89 ab cd ef-01 23 45 67 89   .#Eg.....#Eg."
        printf '%s\n' "$value" | tail -n +2 | sed -E 's/^[0-9a-f]{4} - //; s/   .*$//' | tr -d '\n -' | tr a-f A-F
    else
        printf '%s' "$value"
    fi
}

# check_response <name> <response> <content> <digest>: the response verifies with only its own certificates,
# carries exactly the RA certificate (Mocana needs it), signs the content with the digest and has the SCEP attributes
check_response() {
    if openssl cms -verify -inform DER -in "$2" -noverify -binary -out content.out >/dev/null 2>&1; then
        pass "$1: verifies with only its own certificates"
    else
        fail "$1: verifies with only its own certificates"
    fi
    if cmp -s content.out "$3"; then pass "$1: signs the content"; else fail "$1: signs the content"; fi
    check "$1: carries exactly the RA certificate" "$(openssl pkcs7 -inform DER -in "$2" -print_certs 2>/dev/null | openssl x509 -noout -fingerprint -sha256 2>/dev/null)" "$RA_FINGERPRINT"
    check "$1: certificate count" "$(openssl pkcs7 -inform DER -in "$2" -print_certs 2>/dev/null | grep -c 'BEGIN CERTIFICATE')" "1"
    check "$1: digest algorithm" "$(openssl cms -cmsout -print -inform DER -in "$2" | sed -n '/signerInfos:/,$p' | grep -m1 -A1 'digestAlgorithm:' | sed -n 's/.*algorithm: \([a-z0-9]*\).*/\1/p')" "$4"
    check "$1: messageType CertRep" "$(attr "$2" 2.16.840.1.113733.1.9.2)" "PRINTABLESTRING:3"
    check "$1: senderNonce" "$(attr "$2" 2.16.840.1.113733.1.9.5)" "$SENDERNONCE"
    check "$1: recipientNonce" "$(attr "$2" 2.16.840.1.113733.1.9.6)" "$RECIPIENTNONCE"
    check "$1: transactionID" "$(attr "$2" 2.16.840.1.113733.1.9.7)" "PRINTABLESTRING:$TRANSID"
}

for DIGEST in sha1 sha256 sha512; do
    N="SUCCESS $DIGEST"
    rm -f resp.p7b
    printf '%s\n' "$PASSWORD" | dotnet "$CMSSIGN" ra.pfx stdin cert.p7b $SENDERNONCE $RECIPIENTNONCE "$TRANSID" resp.p7b $DIGEST > out.txt 2> err.txt
    check "$N: exit code" "$?" "0"
    check_response "$N" resp.p7b cert.p7b $DIGEST
    check "$N: pkiStatus SUCCESS" "$(attr resp.p7b 2.16.840.1.113733.1.9.3)" "PRINTABLESTRING:0"
    check "$N: Microsoft status Issued" "$(attr resp.p7b 1.3.6.1.4.1.311.21.38)" "UTF8STRING:Issued"

    N="FAILURE $DIGEST"
    rm -f resp.p7b
    printf '%s\n' "$PASSWORD" | dotnet "$CMSSIGN" ra.pfx stdin empty.asn1 $SENDERNONCE $RECIPIENTNONCE "$TRANSID" resp.p7b 2 2 -2146893819 $DIGEST > out.txt 2> err.txt
    check "$N: exit code" "$?" "0"
    check_response "$N" resp.p7b empty.asn1 $DIGEST
    check "$N: pkiStatus FAILURE" "$(attr resp.p7b 2.16.840.1.113733.1.9.3)" "PRINTABLESTRING:2"
    check "$N: failInfo" "$(attr resp.p7b 2.16.840.1.113733.1.9.4)" "PRINTABLESTRING:2"
    check "$N: Microsoft failInfo text" "$(attr resp.p7b 1.3.6.1.4.1.311.21.33)" "PRINTABLESTRING:-2146893819"
done

# the digest defaults to SHA-256
rm -f resp.p7b
printf '%s\n' "$PASSWORD" | dotnet "$CMSSIGN" ra.pfx stdin cert.p7b $SENDERNONCE $RECIPIENTNONCE "$TRANSID" resp.p7b md5 > out.txt 2> err.txt
check "An unknown digest exits 0" "$?" "0"
check_response "Unknown digest" resp.p7b cert.p7b sha256

# the password as an argument still works
rm -f resp.p7b
dotnet "$CMSSIGN" ra.pfx "$PASSWORD" cert.p7b $SENDERNONCE $RECIPIENTNONCE "$TRANSID" resp.p7b sha256 < /dev/null > out.txt 2> err.txt
check "Password as an argument: exit code" "$?" "0"
check_response "Password as an argument" resp.p7b cert.p7b sha256

# errors: exit 1, no response, and no password or stack trace in the output pkiaas logs
# expect_error <name> <stdin> <args...>
expect_error() {
    local name="$1" input="$2"
    shift 2
    rm -f resp.p7b
    printf '%s' "$input" | dotnet "$CMSSIGN" "$@" > out.txt 2> err.txt
    check "$name: exit code" "$?" "1"
    if [ -f resp.p7b ]; then fail "$name: writes no response"; else pass "$name: writes no response"; fi
    if [ -s err.txt ]; then pass "$name: reports an error on stderr"; else fail "$name: reports an error on stderr"; fi
    if grep -qF -e "$PASSWORD" -e "wrong-$PASSWORD" out.txt err.txt; then fail "$name: no password in the output"; else pass "$name: no password in the output"; fi
    if grep -q '   at ' err.txt; then fail "$name: no stack trace"; else pass "$name: no stack trace"; fi
}
expect_error "Wrong password on stdin" "wrong-$PASSWORD"$'\n' ra.pfx stdin cert.p7b $SENDERNONCE $RECIPIENTNONCE "$TRANSID" resp.p7b sha256
expect_error "Wrong password as an argument" "" ra.pfx "wrong-$PASSWORD" cert.p7b $SENDERNONCE $RECIPIENTNONCE "$TRANSID" resp.p7b sha256
expect_error "No password on stdin" "" ra.pfx stdin cert.p7b $SENDERNONCE $RECIPIENTNONCE "$TRANSID" resp.p7b sha256
expect_error "Missing PFX" "$PASSWORD"$'\n' missing.pfx stdin cert.p7b $SENDERNONCE $RECIPIENTNONCE "$TRANSID" resp.p7b sha256
expect_error "Missing content file" "$PASSWORD"$'\n' ra.pfx stdin missing.p7b $SENDERNONCE $RECIPIENTNONCE "$TRANSID" resp.p7b sha256
rm -f resp.p7b
dotnet "$CMSSIGN" < /dev/null > out.txt 2> err.txt
check "No arguments: exit code" "$?" "1"

echo "Results: $PASSED passed, $FAILED failed"
[ "$FAILED" -eq 0 ]
