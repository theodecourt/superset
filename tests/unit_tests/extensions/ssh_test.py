# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
from unittest.mock import Mock

import paramiko
import pytest
import sshtunnel

import superset.extensions.ssh as ssh_module
from superset.extensions.ssh import _apply_sha1_mitigation, SSHManagerFactory


def test_ssh_tunnel_timeout_setting() -> None:
    app = Mock()
    app.config = {
        "SSH_TUNNEL_MAX_RETRIES": 2,
        "SSH_TUNNEL_LOCAL_BIND_ADDRESS": "test",
        "SSH_TUNNEL_TIMEOUT_SEC": 123.0,
        "SSH_TUNNEL_PACKET_TIMEOUT_SEC": 321.0,
        "SSH_TUNNEL_MANAGER_CLASS": "superset.extensions.ssh.SSHManager",
    }
    factory = SSHManagerFactory()
    factory.init_app(app)
    assert sshtunnel.TUNNEL_TIMEOUT == 123.0
    assert sshtunnel.SSH_TIMEOUT == 321.0


def test_sha1_mitigation_patches_transport(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """_apply_sha1_mitigation replaces Transport.__init__ to disable ssh-rsa."""
    monkeypatch.setattr(ssh_module, "_SHA1_PATCH_APPLIED", False)
    original_init = paramiko.Transport.__init__

    try:
        _apply_sha1_mitigation()
        assert paramiko.Transport.__init__ is not original_init
        assert ssh_module._SHA1_PATCH_APPLIED is True
    finally:
        paramiko.Transport.__init__ = original_init  # type: ignore[method-assign]
        monkeypatch.setattr(ssh_module, "_SHA1_PATCH_APPLIED", False)


def test_sha1_mitigation_is_idempotent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Calling _apply_sha1_mitigation twice does not double-patch."""
    monkeypatch.setattr(ssh_module, "_SHA1_PATCH_APPLIED", True)
    original_init = paramiko.Transport.__init__
    _apply_sha1_mitigation()
    assert paramiko.Transport.__init__ is original_init
