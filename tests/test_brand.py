from pathlib import Path
import struct

ROOT = Path(__file__).parents[1]
BRAND = ROOT / "custom_components" / "home_assistant_chat" / "brand"

def png_size(path):
    data=path.read_bytes()
    assert data[:8] == b"\x89PNG\r\n\x1a\n"
    return struct.unpack(">II",data[16:24])

def test_local_brand_images_have_expected_dimensions():
    assert png_size(BRAND / "icon.png") == (128,128)
    assert png_size(BRAND / "logo.png") == (250,100)
