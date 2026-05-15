import os
import requests

# Environment variables
NETBOX_URL = os.environ.get("NETBOX_URL", "")
NETBOX_TOKEN = os.environ.get("NETBOX_API", "")

# Input variables
DEVICE_NAME = "umc-dnt-5394-nk9300-01"
INTERFACE_NAME = "Ethernet1/1"
NEW_MAC_ADDRESS = "AA:BB:CC:DD:EE:FF"

# Headers
headers = {
    "Authorization": f"Token {NETBOX_TOKEN}",
    "Content-Type": "application/json"
}

def get_interface_id(device_name, interface_name):
    """Fetch interface ID from NetBox"""
    url = f"{NETBOX_URL}/api/dcim/interfaces/"
    params = {
        "device": device_name,
        "name": interface_name
    }
    
    response = requests.get(url, headers=headers, params=params, verify=False)
    response.raise_for_status()
    
    data = response.json()
    if data["count"] == 0:
        raise Exception(f"Interface {interface_name} not found on {device_name}")
    
    return data["results"][0]["id"]

def create_mac_address(interface_id, mac_address):
    """Create MAC address and assign it to interface"""
    url = f"{NETBOX_URL}/api/dcim/mac-addresses/"
    
    payload = {
        "mac_address": mac_address,
        "assigned_object_type": "dcim.interface",
        "assigned_object_id": interface_id,
        "description": "Added via API"
    }
    
    response = requests.post(url, headers=headers, json=payload, verify=False)
    
    if response.status_code not in [200, 201]:
        raise Exception(f"Failed to create MAC: {response.text}")
    
    return response.json()

def main():
    try:
        print(f"Finding interface: {DEVICE_NAME} {INTERFACE_NAME}")
        interface_id = get_interface_id(DEVICE_NAME, INTERFACE_NAME)
        
        print(f"Interface ID: {interface_id}")
        print(f"Adding MAC address: {NEW_MAC_ADDRESS}")
        
        result = create_mac_address(interface_id, NEW_MAC_ADDRESS)
        
        print("✅ MAC address created successfully")
        print(f"MAC ID: {result['id']}")
        print(f"Assigned to interface ID: {result['assigned_object_id']}")
    
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    main()