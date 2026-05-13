import configparser
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def _platformio_config() -> configparser.ConfigParser:
    config = configparser.ConfigParser(interpolation=None, strict=False)
    config.optionxform = str
    config.read(REPO_ROOT / "lib" / "node_types" / "esp" / "platformio.ini")
    return config


def test_esp32_envs_inherit_generated_extra_build_flags():
    config = _platformio_config()
    esp32_envs = [
        "env:esp32",
        "env:m5stickc",
        "env:m5stickc_plus",
        "env:m5stickc_plus2",
        "env:esp32dev",
        "env:esp32minikit",
        "env:esp32_c3_devkitm_1",
        "env:esp32_c6_devkitm_1",
        "env:lolin_s2_mini",
    ]

    for section in esp32_envs:
        assert "${common.extra_build_flags}" in config[section]["build_flags"]


def test_esp32_minikit_and_devkit_ignore_unused_bundled_ble_library():
    config = _platformio_config()

    for section in ["env:esp32dev", "env:esp32minikit"]:
        ignored_libraries = config[section]["lib_ignore"].splitlines()
        assert "ESP32 BLE Arduino" in ignored_libraries
