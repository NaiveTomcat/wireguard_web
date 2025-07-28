import wgconfig as wgc  # type: ignore
from wgconfig import wgexec as wgexec  # type: ignore
import ipaddress
import os
import configparser

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
    
def get_peers_comment(config:configparser.SectionProxy):
    """
    Get the comments of all peers in the WireGuard configuration.
    
    Args:
        config (configparser.SectionProxy): Configuration section proxy object for the WireGuard config file.
    
    Returns:
        list: A list of tuples containing the peer public key, its IP Address and its comment.

    Raises:
        ValueError: If the configuration file path is not provided.
        Exception: If there is an error reading the configuration file.
    """
    if not config.get('WireGuardInterface'):
        raise ValueError("Configuration file path must be provided. Current value: {}".format(config.get('WireGuardInterface')))
    # if not os.path.exists(config['WireGuardInterface']):
    #     raise ValueError("Configuration file does not exist. current value: {}".format(config['WireGuardInterface']))
    try:
        serverconfig = wgc.WGConfig(config['WireGuardInterface'])
        serverconfig.read_file()
        peers = serverconfig.get_peers(keys_only=False, include_details=True)
        peerinfo = [(peer, peers.get(peer, {}).get('AllowedIPs'), peers.get(peer, {}).get('_rawdata')[0].strip()) for peer in peers]
        return peerinfo
    except Exception as e:
        raise Exception(f"Error reading WireGuard configuration: {e}")
        
    

def add_peer(config:configparser.SectionProxy, clientaddr:str, comment=None):
    """
    Add a new peer to the WireGuard configuration.
    
    Args:
        config (configparser.SectionProxy): Configuration section proxy object for the WireGuard config file.
        clientaddr (str): The address to be assigned to the client.

    Returns:
        str: The generated client configuration string.

    Raises:
        ValueError: If the configuration file path is not provided or if the client address is not valid.
        Exception: If there is an error while generating the key pair or reading/writing the configuration file.
    """

    if not config.get('WireGuardInterface') or not clientaddr or not is_valid_ipv4(clientaddr):
        raise ValueError("Configuration file path and client address must be correctly provided.")
    
    try:

        ClientPriv, ClientPub = wgexec.generate_keypair()
        ServerConfig = wgc.WGConfig(config['WireGuardInterface'])
        ServerConfig.read_file()
        ServerPubkey = wgexec.get_publickey(ServerConfig.interface['PrivateKey'])

        LanCIDR = config.get('LanCIDR')
        ServerEndpoint = config.get('ServerEndpoint')
        client_config = ClientTemplate.format(
            privkey=ClientPriv,
            clientaddr=clientaddr,
            serverpubkey=ServerPubkey,
            lancidr=LanCIDR,
            serverendpoint=ServerEndpoint
        )

        ServerConfig.read_file()
        ServerConfig.add_peer(ClientPub, comment)
        ServerConfig.add_attr(ClientPub, 'AllowedIPs', f'{clientaddr}/32')
        ServerConfig.write_file()
    except Exception as e:
        raise e
    if config.getboolean('RestartWG', fallback=False):
        try:
            os.system(f"sudo wg-quick down {config['WireGuardInterface']} && sudo wg-quick up {config['WireGuardInterface']}")
        except Exception as e:
            raise Exception(f"Error restarting WireGuard: {e}")

    return client_config


def del_peer(config:configparser.SectionProxy, clientpubkey:str):
    """
    Delete a peer from the WireGuard configuration.
    
    Args:
        config (configparser.SectionProxy): Configuration section proxy object for the WireGuard config file.
        clientpubkey (str): The public key of the client to be removed.

    Raises:
        ValueError: If the configuration file path is not provided or if the client public key is not valid.
        Exception: If there is an error reading or writing the configuration file.
    """
    if not config.get('WireGuardInterface') or not clientpubkey:
        raise ValueError("Configuration file path and client public key must be provided.")
    
    try:
        serverconfig = wgc.WGConfig(config.get('WireGuardInterface'))
        serverconfig.read_file()
        serverconfig.del_peer(clientpubkey)
        serverconfig.write_file()
    except Exception as e:
        raise Exception(f"Error deleting peer: {e}")
    
    if config.getboolean('RestartWG', fallback=False):
        try:
            os.system(f"sudo wg-quick down {config.get('WireGuardInterface')} && sudo wg-quick up {config.get('WireGuardInterface')}")
        except Exception as e:
            raise Exception(f"Error restarting WireGuard: {e}")



