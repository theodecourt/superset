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

import functools
import logging
from io import StringIO
from typing import Any, TYPE_CHECKING

import paramiko
import sshtunnel
from flask import Flask
from paramiko import RSAKey

from superset.commands.database.ssh_tunnel.exceptions import SSHTunnelDatabasePortError
from superset.databases.utils import make_url_safe
from superset.utils.class_utils import load_class_from_name

if TYPE_CHECKING:
    from superset.databases.ssh_tunnel.models import SSHTunnel


_SHA1_PATCH_APPLIED = False

# Default algorithms to disable in paramiko Transport (CVE-2026-44405).
# Removing "ssh-rsa" prevents negotiation of the SHA-1-based signature
# scheme, matching the behaviour of paramiko >=5.0.0.
_DEFAULT_DISABLED_ALGORITHMS: dict[str, list[str]] = {
    "keys": ["ssh-rsa"],
    "pubkeys": ["ssh-rsa"],
}


def _apply_sha1_mitigation(
    disabled_algorithms: dict[str, list[str]] | None = None,
) -> None:
    """Patch paramiko Transport to disable SHA-1 RSA algorithms.

    Workaround for CVE-2026-44405 while paramiko < 5.0.0 is required
    due to sshtunnel 0.4.0 incompatibility with paramiko >= 4.0.0.
    """
    global _SHA1_PATCH_APPLIED  # noqa: PLW0603
    if _SHA1_PATCH_APPLIED:
        return

    algorithms = disabled_algorithms or _DEFAULT_DISABLED_ALGORITHMS
    _original_init = paramiko.Transport.__init__

    @functools.wraps(_original_init)
    def _patched_init(self: paramiko.Transport, *args: Any, **kwargs: Any) -> None:
        if "disabled_algorithms" not in kwargs:
            kwargs["disabled_algorithms"] = algorithms
        _original_init(self, *args, **kwargs)

    paramiko.Transport.__init__ = _patched_init  # type: ignore[method-assign]
    _SHA1_PATCH_APPLIED = True


class SSHManager:
    def __init__(self, app: Flask) -> None:
        super().__init__()
        self.local_bind_address = app.config["SSH_TUNNEL_LOCAL_BIND_ADDRESS"]
        sshtunnel.TUNNEL_TIMEOUT = app.config["SSH_TUNNEL_TIMEOUT_SEC"]
        sshtunnel.SSH_TIMEOUT = app.config["SSH_TUNNEL_PACKET_TIMEOUT_SEC"]
        _apply_sha1_mitigation(
            app.config.get("SSH_TUNNEL_DISABLED_ALGORITHMS"),
        )

    def build_sqla_url(
        self, sqlalchemy_url: str, server: sshtunnel.SSHTunnelForwarder
    ) -> str:
        # override any ssh tunnel configuration object
        url = make_url_safe(sqlalchemy_url)
        return url.set(
            host=server.local_bind_address[0],
            port=server.local_bind_port,
        )

    def create_tunnel(
        self,
        ssh_tunnel: "SSHTunnel",
        sqlalchemy_database_uri: str,
    ) -> sshtunnel.SSHTunnelForwarder:
        from superset.utils.ssh_tunnel import get_default_port

        url = make_url_safe(sqlalchemy_database_uri)
        backend = url.get_backend_name()
        port = url.port or get_default_port(backend)
        if not port:
            raise SSHTunnelDatabasePortError()
        params = {
            "ssh_address_or_host": (ssh_tunnel.server_address, ssh_tunnel.server_port),
            "ssh_username": ssh_tunnel.username,
            "remote_bind_address": (url.host, port),
            "local_bind_address": (self.local_bind_address,),
            "debug_level": logging.getLogger("flask_appbuilder").level,
        }

        if ssh_tunnel.password:
            params["ssh_password"] = ssh_tunnel.password
        elif ssh_tunnel.private_key:
            private_key_file = StringIO(ssh_tunnel.private_key)
            private_key = RSAKey.from_private_key(
                private_key_file, ssh_tunnel.private_key_password
            )
            params["ssh_pkey"] = private_key

        return sshtunnel.open_tunnel(**params)


class SSHManagerFactory:
    def __init__(self) -> None:
        self._ssh_manager = None

    def init_app(self, app: Flask) -> None:
        self._ssh_manager = load_class_from_name(
            app.config["SSH_TUNNEL_MANAGER_CLASS"]
        )(app)

    @property
    def instance(self) -> SSHManager:
        return self._ssh_manager  # type: ignore
