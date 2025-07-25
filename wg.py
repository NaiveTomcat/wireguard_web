import wgconfig as wgc
from wgconfig import wgexec as wgexec
import ipaddress
import os

ClientTemplate = """[Interface]
PrivateKey = {privkey}
Address = {clientaddr}

[Peer]
PublicKey = {serverpubkey}
AllowedIPs = {lancidr}
Endpoint = {serverendpoint}
PersistentKeepalive = 15
"""

def is_valid_ipv4(ip_string):
    """
    Checks if a given string is a valid IPv4 address.
    """
    try:
        ipaddress.IPv4Address(ip_string)
        return True
    except ipaddress.AddressValueError:
        return False

def update_config_file(config:dict, clientaddr:str, comment=None):
    """
    Update the WireGuard configuration file with given config and client address.
    
    Args:
        config (dict): Configuration dictionary containing keys like 'serverpubkey', 'lancidr', 'serverendpoint', and path to the WireGuard config file.
        clientaddr (str): The address to be assigned to the client.

    Returns:
        str: The generated client configuration string.

    Raises:
        ValueError: If the configuration file path is not provided or if the client address is not valid.
        Exception: If there is an error while generating the key pair or reading/writing the configuration file.
    """

    if not config.get('wgconfigfile') or not clientaddr or not is_valid_ipv4(clientaddr):
        raise ValueError("Configuration file path and client address must be correctly provided.")
    
    try:

        client_priv, client_pub = wgexec.generate_keypair()
        serverconfig = wgc.WGConfig(config['wgconfigfile'])
        serverpubkey = wgexec.get_publickey(serverconfig.get_interface()['PrivateKey'])

        lancidr = config['lancidr']
        serverendpoint = config['serverendpoint']
        client_config = ClientTemplate.format(
            privkey=client_priv,
            clientaddr=clientaddr,
            serverpubkey=serverpubkey,
            lancidr=lancidr,
            serverendpoint=serverendpoint
        )

        serverconfig.read_file()
        serverconfig.add_peer(client_pub, comment)
        serverconfig.add_attr(client_pub, 'AllowedIPs', f'{clientaddr}/32')
        serverconfig.write_file()
    except Exception as e:
        raise Exception(f"Error generating client configuration: {e}")
    try:
        os.system(f"sudo wg-quick down {config['wgconfigfile']} && sudo wg-quick up {config['wgconfigfile']}")
    except Exception as e:
        raise Exception(f"Error restarting WireGuard: {e}")

    return client_config



