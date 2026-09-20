from pathlib import Path


SOURCE = (Path(__file__).parents[1] / "custom_components/home_assistant_chat/__init__.py").read_text()


def test_setup_loads_and_registers_store_before_panel():
    load = SOURCE.index("await store.async_load()")
    register_store = SOURCE.index("await store.async_register()")
    register_panel = SOURCE.index("await async_register_panel(hass, entry.entry_id)")
    assert load < register_store < register_panel
