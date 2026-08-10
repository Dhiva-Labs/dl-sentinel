import yaml


def load_config_safe(raw_text):
    return yaml.load(raw_text, Loader=yaml.SafeLoader)


def load_config_safest(raw_text):
    return yaml.safe_load(raw_text)
