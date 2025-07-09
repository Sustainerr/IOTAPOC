import base64
import json
from nacl.signing import VerifyKey
from nacl.exceptions import BadSignatureError

# JWT
jwt_token = (
    "eyJraWQiOiJkaWQ6aW90YTp0c3Q6MHhmOWIxYThhZDgxOGUxZThmZDI1MDRhYmNhODkzZWQ5ZjA2MTgxODVhZjliZmUyMTQ4ZjkzMzhkMzMwODc0NGMxI2tleS1pc3N1ZXIiLCJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSJ9."
    "eyJpc3MiOiJkaWQ6aW90YTp0c3Q6MHhmOWIxYThhZDgxOGUxZThmZDI1MDRhYmNhODkzZWQ5ZjA2MTgxODVhZjliZmUyMTQ4ZjkzMzhkMzMwODc0NGMxIiwibmJmIjoxNzUxNjIxMTMyLCJqdGkiOiJodHRwczovL2V4YW1wbGUub3JnL2NyZWRlbnRpYWxzL3ZlaGljbGUtYXV0aCIsInN1YiI6ImRpZDppb3RhOnRzdDoweDA4ODczOWZlMTg1NjY5NGIzMDA4OGYzODk2NWQ2YjU3ZDdlNTczZDExMzBhNWRhMDZlYzRmN2M4ZmUxNTE4ZTEiLCJ2YyI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSJdLCJ0eXBlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIiwiVmVoaWNsZUF1dGhvcml6YXRpb24iXSwiY3JlZGVudGlhbFN1YmplY3QiOnsidmVoaWNsZSI6eyJhdXRob3JpemVkIjp0cnVlLCJtcXR0X3RvcGljIjoibXF0dC90b3BpYy92ZWhpY2xlIn19fX0."
    "136HybgOsQSMp3UZ19EBKGQu0YYsOX3fjaTpknOfayjULmcRj7Z7yFK3AMHPZLydqou-8atQSdHncdFbCPL9Cg"
)

# Ed25519 public key (from DID doc, base64url -> raw bytes)
x_b64url = "-xb0ktZIWDlxtAd86yiQSRrS7bkB3m2xnKPKwB_V7qo"
x_bytes = base64.urlsafe_b64decode(x_b64url + '==')  # pad safely

# Split JWT
header_b64, payload_b64, signature_b64 = jwt_token.split(".")

# Reconstruct signing input (header + "." + payload)
signing_input = f"{header_b64}.{payload_b64}".encode("utf-8")
signature = base64.urlsafe_b64decode(signature_b64 + '==')  # pad safely

# Verify signature
verify_key = VerifyKey(x_bytes)
try:
    verify_key.verify(signing_input, signature)
    print("✅ Signature is VALID")
    payload_json = base64.urlsafe_b64decode(payload_b64 + '==').decode()
    claims = json.loads(payload_json)
    print("📦 Claims:", json.dumps(claims, indent=2))
except BadSignatureError:
    print("❌ Signature is INVALID")
