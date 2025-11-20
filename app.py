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

def verify_shopify_webhook(raw_body, hmac_header):
    digest = hmac.new(
        SHOPIFY_WEBHOOK_SECRET.encode(),
        raw_body,
        hashlib.sha256
    ).digest()
    computed = base64.b64encode(digest).decode()
    return hmac.compare_digest(computed, hmac_header or "")

def shopify_rest(method, path, params=None, json_body=None):
    url = f"https://{SHOPIFY_SHOP}/admin/api/{SHOPIFY_API_VERSION}/{path}"
    headers = {
        "X-Shopify-Access-Token": SHOPIFY_ACCESS_TOKEN,
        "Content-Type": "application/json"
    }
    resp = requests.request(method, url, headers=headers, params=params, json=json_body)
    if not resp.ok:
        app.logger.error(resp.text)
        resp.raise_for_status()
    if resp.text.strip():
        return resp.json()
    return {}

def shopify_graphql(query, variables):
    url = f"https://{SHOPIFY_SHOP}/admin/api/{SHOPIFY_API_VERSION}/graphql.json"
    headers = {
        "X-Shopify-Access-Token": SHOPIFY_ACCESS_TOKEN,
        "Content-Type": "application/json"
    }
    resp = requests.post(url, headers=headers, json={"query": query, "variables": variables})
    data = resp.json()
    if "errors" in data:
        raise RuntimeError(data["errors"])
    return data["data"]

def gid_to_id(gid):
    return gid.split("/")[-1]

def get_product_inventory_items(inventory_item_id):
    gid = f"gid://shopify/InventoryItem/{inventory_item_id}"
    query = """
    query ($id: ID!) {
      inventoryItem(id: $id) {
        variant {
          product {
            id
            variants(first: 100) {
              edges {
                node {
                  inventoryItem { id }
                }
              }
            }
          }
        }
      }
    }
    """
    data = shopify_graphql(query, {"id": gid})
    product_gid = data["inventoryItem"]["variant"]["product"]["id"]
    product_id = gid_to_id(product_gid)

    items = []
    for edge in data["inventoryItem"]["variant"]["product"]["variants"]["edges"]:
        invgid = edge["node"]["inventoryItem"]["id"]
        items.append(gid_to_id(invgid))

    return product_id, items

def has_israel_stock(inv_ids):
    params = {
        "location_ids": ISRAEL_LOCATION_ID,
        "inventory_item_ids": ",".join(inv_ids)
    }
    data = shopify_rest("GET", "inventory_levels.json", params=params)
    for lvl in data.get("inventory_levels", []):
        if str(lvl["location_id"]) == str(ISRAEL_LOCATION_ID):
            if lvl["available"] > 0:
                return True
    return False

def update_product_tag(product_id, in_stock):
    data = shopify_rest("GET", f"products/{product_id}.json", params={"fields": "id,tags"})
    tags = data["product"]["tags"].split(",")
    tags = [t.strip() for t in tags if t.strip()]

    changed = False
    if in_stock and "Stock" not in tags:
        tags.append("Stock")
        changed = True
    elif not in_stock and "Stock" in tags:
        tags.remove("Stock")
        changed = True

    if changed:
        shopify_rest("PUT", f"products/{product_id}.json", json_body={
            "product": {
                "id": int(product_id),
                "tags": ", ".join(tags)
            }
        })

@app.route("/webhooks/inventory", methods=["POST"])
def webhook():
    raw = request.get_data()
    hmac_header = request.headers.get("X-Shopify-Hmac-Sha256", "")
    if not verify_shopify_webhook(raw, hmac_header):
        abort(401)

    payload = json.loads(raw.decode())
    if str(payload["location_id"]) != str(ISRAEL_LOCATION_ID):
        return "", 200

    inv_item = payload["inventory_item_id"]
    product_id, all_items = get_product_inventory_items(inv_item)
    in_stock = has_israel_stock(all_items)
    update_product_tag(product_id, in_stock)

    return "", 200

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
