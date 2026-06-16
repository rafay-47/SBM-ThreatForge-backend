import os

# Load .env file if present
try:
    from dotenv import load_dotenv
    _env_path = os.path.join(os.path.dirname(__file__), "..", ".env")
    if os.path.exists(_env_path):
        load_dotenv(_env_path, override=True)
except ImportError:
    pass


def get_env(name: str, default=None, strip: bool = True):
    """Read an environment variable with optional whitespace trimming."""
    value = os.environ.get(name)
    if value is None:
        return default

    if not strip:
        return value

    normalized = value.strip()
    return normalized if normalized else default


def get_region(default: str = "us-east-1") -> str:
    """Resolve region from common environment variables."""
    return (
        get_env("REGION")
        or get_env("AWS_REGION")
        or get_env("AWS_DEFAULT_REGION")
        or default
    )


def get_deployment_mode(default: str = "local") -> str:
    """Resolve deployment mode with normalized lowercase value."""
    return (get_env("DEPLOYMENT_MODE", default) or default).strip().lower()
