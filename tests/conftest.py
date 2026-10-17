import pytest

import app.backend.pipeline  # noqa: F401  (registers backend/stub reset hooks)
from app.controls import controls
from app.services.data import reset_data


@pytest.fixture(autouse=True)
def isolated_data(tmp_path, monkeypatch):
    monkeypatch.setenv("IR_DATA_DIR", str(tmp_path))
    reset_data()
    controls.slow_delay_s = 0.05
    yield
    reset_data()
