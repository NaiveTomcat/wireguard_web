import configparser

def load_config(file_path: str) -> configparser.ConfigParser:
    """
    Load configuration from a file.

    Args:
        file_path (str): Path to the configuration file.

    Returns:
        configparser.ConfigParser: Parsed configuration object.
    """
    config = configparser.ConfigParser()
    config.read(file_path)
    return config
