import os
import pytest
from host_access.config import Config, protected, load


def test_defaults_and_invalid_origin():
    c = Config(origin='https://approve.example', agent_uid=123, web_uid=124)
    assert c.default_duration == 900 and c.maximum_duration == 1800
    assert not c.enable_script and not c.log_services
    assert c.trusted_proxy == '127.0.0.1'
    assert Config(origin='https://example',agent_uid=123,web_uid=124,bind='0.0.0.0',trusted_proxy='192.0.2.10')
    with pytest.raises(ValueError):
        Config(origin='https://example',agent_uid=123,web_uid=124,trusted_proxy='*')
    with pytest.raises(ValueError):
        Config(origin='https://example',agent_uid=123,web_uid=124,enable_script='false')
    for origin in ['http://approve.example', 'https://user:pass@example', 'https://example/path']:
        with pytest.raises(ValueError):
            Config(origin=origin, agent_uid=123, web_uid=124)
    with pytest.raises(ValueError):
        Config(origin='https://example', agent_uid=123, web_uid=123)


def test_protected_file_and_symlink(tmp_path):
    p = tmp_path / 'config'
    p.write_text('origin="https://example"\nagent_uid=123\nweb_uid=124\n')
    p.chmod(0o600)
    assert load(p, owner=os.getuid()).agent_uid == 123
    link = tmp_path / 'link'
    link.symlink_to(p)
    with pytest.raises(ValueError):
        protected(link, owner=os.getuid())
    p.chmod(0o666)
    with pytest.raises(ValueError):
        load(p, owner=os.getuid())
