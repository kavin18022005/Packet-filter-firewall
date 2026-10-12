import os
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    PROJECT_NAME: str = "Data-Driven Packet Filtering Firewall"
    DATABASE_URL: str = "sqlite:///./firewall.db"
    DEFAULT_POLICY: str = "BLOCK"  # BLOCK or ALLOW
    PORT_SCAN_THRESHOLD: int = 5   # Distinct destination ports from same IP in window
    PORT_SCAN_WINDOW_SECONDS: int = 30
    SYN_FLOOD_THRESHOLD: int = 15  # SYN packets from same IP in window
    SIMULATOR_RATE_MS: int = 1000  # Interval between synthetic packet batches in ms
    SIMULATOR_BATCH_SIZE: int = 3  # Packets per cycle
    LIVE_CAPTURE_ENABLED: bool = False

settings = Settings()
