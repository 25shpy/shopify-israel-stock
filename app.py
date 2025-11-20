import os
import hmac
import hashlib
import base64
import json
import logging

from flask import Flask, request, abort
import requests
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)

SHOPIFY_SHOP = os.environ.get("SHOPIFY_SHOP")
SHOPIFY_API_VERSION = os.environ.get("SHOPIFY_API_VERSION", "2025-01")
SHOPIFY_ACCESS_TOKEN = os.environ.get("SHOPIFY_ACCESS_TOKEN")
SHOPIFY_WEBHOOK_SECRET = os.environ.get("SHOPIFY_WEBHOOK_SECRET")
ISRAEL_LOCATION_ID = os.environ.get("ISRAEL_LOCATION_ID")

if not all([SHOPIFY_SHOP, SHOPIFY_ACCESS_TOKEN, SHOPIFY_WEBHOOK_SECRET, ISRAEL_LOCATION_ID]):
    raise RuntimeError("Missing environment variables")


# --------------------------------------------------------
#  Shopify yardımcıları
# --------------------------------------------------------
def verify_shopify_webhook(raw_body, hmac_header):
    """Shopify HMAC doğrulaması."""
    digest = hmac.new(
        SHOPIFY_WEBHOOK_SECRET.encode(),
        raw_body,
        hashlib.sha256
    ).digest()
    computed = base64.b64encode(digest).decode()
    return hmac.compare_digest(computed, hmac_header or "")


def shopify_rest(method, path, params=None, json_body=None):
    """Shopify REST çağrısı (Admin API)."""
    url = f"https://{SHOPIFY_SHOP}/admin/api/{SHOPIFY_API_VERSION}/{path}"
    headers = {
        "X-Shopify-Access-Token": SHOPIFY_ACCESS_TOKEN,
        "Content-Type": "application/json"
    }
    resp = requests.request(method, url, headers=headers, params=params, json=json_body)
    if not resp.ok:
        app.logger.error(f"REST error {resp.status_code}: {resp.text}")
        resp.raise_for_status()
    if resp.text.strip():
        return resp.json()
    return {}


def shopify_graphql(query, variables):
    """Shopify GraphQL çağrısı."""
    url = f"https://{SHOPIFY_SHOP}/admin/api/{SHOPIFY_API_VERSION}/graphql.json"
    headers = {
        "X-Shopify-Access-Token": SHOPIFY_ACCESS_TOKEN,
        "Content-Type": "application/json"
    }
    resp = requests.post(url, headers=headers, json={"query": query, "variables": variables})
    data = resp.json()
    if "errors" in data:
        app.logger.error(f"GraphQL errors: {data['errors']}")
        raise RuntimeError(data["errors"])
    return data["data"]


def gid_to_id(gid: str) -> str:
    """gid://shopify/Variant/1234567890 -> 1234567890"""
    return gid.split("/")[-1]


# --------------------------------------------------------
#  inventory_item_id -> variant_id
# --------------------------------------------------------
def get_variant_id_from_inventory_item(inventory_item_id: int) -> str:
    """
    Verilen inventory_item_id'ye bağlı tek bir variant_id döndürür.
    """
    gid = f"gid://shopify/InventoryItem/{inventory_item_id}"
    query = """
    query ($id: ID!) {
      inventoryItem(id: $id) {
        variant {
          id
        }
      }
    }
    """
    data = shopify_graphql(query, {"id": gid})
    inv_item = data.get("inventoryItem")
    if not inv_item or not inv_item.get("variant"):
        raise RuntimeError(f"No variant found for inventory_item_id={inventory_item_id}")

    variant_gid = inv_item["variant"]["id"]
    variant_id = gid_to_id(variant_gid)
    return variant_id


# --------------------------------------------------------
#  Variant metafield (custom.israel_stock)
# --------------------------------------------------------
def set_israel_stock_metafield(variant_id: str, in_israel_stock: bool):
    """
    Variant için custom.israel_stock boolean metafield'ını true/false olarak set eder.
    """
    app.logger.info(
        f"Updating metafield custom.israel_stock for variant {variant_id} => {in_israel_stock}"
    )

    # Önce mevcut metafield var mı diye bak
    params = {
        "namespace": "custom",
        "key": "israel_stock"
    }
    existing = shopify_rest(
        "GET",
        f"variants/{variant_id}/metafields.json",
        params=params
    ).get("metafields", [])

    value_str = "true" if in_israel_stock else "false"

    if existing:
        # Güncelle
        mf_id = existing[0]["id"]
        shopify_rest(
            "PUT",
            f"metafields/{mf_id}.json",
            json_body={
                "metafield": {
                    "id": mf_id,
                    "value": value_str,
                    "type": "boolean"
                }
            }
        )
    else:
        # Yeni oluştur
        shopify_rest(
            "POST",
            f"variants/{variant_id}/metafields.json",
            json_body={
                "metafield": {
                    "namespace": "custom",
                    "key": "israel_stock",
                    "type": "boolean",
                    "value": value_str
                }
            }
        )


# --------------------------------------------------------
#  Webhook endpoint
# --------------------------------------------------------
@app.route("/webhooks/inventory", methods=["POST"])
def webhook():
    raw = request.get_data()
    hmac_header = request.headers.get("X-Shopify-Hmac-Sha256", "")
    if not verify_shopify_webhook(raw, hmac_header):
        app.logger.warning("Invalid HMAC – unauthorized webhook")
        abort(401)

    payload = json.loads(raw.decode())
    app.logger.info(
        f"Received inventory webhook: item {payload.get('inventory_item_id')} "
        f"loc {payload.get('location_id')} avail={payload.get('available')}"
    )

    # Sadece İsrail lokasyonu için çalış
    if str(payload.get("location_id")) != str(ISRAEL_LOCATION_ID):
        app.logger.info("Location is not ISRAEL, skipping.")
        return "", 200

    inv_item = payload.get("inventory_item_id")
    if not inv_item:
        app.logger.warning("No inventory_item_id in payload")
        return "", 200

    available = payload.get("available")
    if available is None:
        app.logger.warning("No 'available' field in payload; skipping metafield update")
        return "", 200

    # İlgili variant_id'yi bul
    try:
        variant_id = get_variant_id_from_inventory_item(inv_item)
    except Exception as e:
        app.logger.error(f"Error getting variant for inventory_item_id={inv_item}: {e}")
        return "", 200

    # İsrail stok durumu
    in_israel_stock = available > 0
    set_israel_stock_metafield(variant_id, in_israel_stock)

    return "", 200

def sync_inventory_simple():
    """
    İsrail lokasyonundaki TÜM inventory_item'ları okuyup
    her biri için custom.israel_stock metafield'ini,
    gerçek 'available > 0' durumuna göre yeniden yazar.
    """
    app.logger.info("Running simple inventory sync for ISRAEL location...")

    # 1) İsrail lokasyonundaki stok seviyelerini çek
    levels_resp = shopify_rest(
        "GET",
        "inventory_levels.json",
        params={
            "location_ids": ISRAEL_LOCATION_ID,
            "limit": 250
        }
    )
    levels = levels_resp.get("inventory_levels", [])
    app.logger.info(f"Fetched {len(levels)} inventory_levels for ISRAEL")

    # 2) Her inventory_item için variant_id bul ve metafield güncelle
    for lvl in levels:
        inv_item_id = lvl.get("inventory_item_id")
        available = lvl.get("available", 0) or 0

        if not inv_item_id:
            continue

        try:
            variant_id = get_variant_id_from_inventory_item(inv_item_id)
        except Exception as e:
            app.logger.error(f"Error getting variant for inventory_item_id={inv_item_id}: {e}")
            continue

        in_israel_stock = available > 0
        set_israel_stock_metafield(variant_id, in_israel_stock)

    app.logger.info("Simple inventory sync for ISRAEL finished.")
    return True


@app.route("/admin/run-sync")
def run_sync_simple():
    try:
        ok = sync_inventory_simple()
        return "Sync OK" if ok else "Sync Error"
    except Exception as e:
        # Hata hem log'a gitsin hem de ekranda görelim
        app.logger.exception("Error in sync_inventory_simple")
        return f"Sync ERROR: {e}", 500







# --------------------------------------------------------
#  Local run
# --------------------------------------------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
