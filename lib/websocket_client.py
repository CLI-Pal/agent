"""
CLI Pal Agent - WebSocket Client Module

WebSocket client for terminal sessions ONLY.
NOT for metrics - those go via REST API (api_client.py).

This handles bidirectional terminal I/O between user browser and server shell.
"""

import os
import sys
import json
import asyncio
import websockets
from typing import Optional


class WebSocketClient:
    """WebSocket client for terminal sessions ONLY

    NOT for metrics - those go via REST API (api_client.py).
    This handles bidirectional terminal I/O.
    """

    def __init__(self, server_url: str, token: str, version: str, terminal_handler, logger):
        """Initialize WebSocket client

        Args:
            server_url: WebSocket server URL (wss://...)
            token: Agent authentication token
            version: Agent version string
            terminal_handler: TerminalHandler instance
            logger: Logger instance
        """
        self.server_url = server_url
        self.token = token
        self.version = version
        self.terminal = terminal_handler
        self.logger = logger
        self.ws: Optional[websockets.WebSocketClientProtocol] = None
        self.connected = False
        self.running = True

    async def run(self) -> None:
        """Main WebSocket loop with reconnection"""
        while self.running:
            try:
                await self._connect()
                await self._message_loop()
            except websockets.exceptions.ConnectionClosed:
                self.logger.info("WebSocket connection closed", always=True)
            except Exception as e:
                self.logger.error(f"WebSocket error: {e}")

            self.connected = False

            if self.running:
                self.logger.info("Reconnecting in 5 seconds...", always=True)
                await asyncio.sleep(5)

    async def _connect(self) -> None:
        """Establish WebSocket connection"""
        self.logger.info(f"Connecting to {self.server_url}...", always=True)

        uri = f"{self.server_url}?token={self.token}&agent_version={self.version}"

        self.ws = await websockets.connect(
            uri,
            ping_interval=20,
            ping_timeout=10
        )
        self.connected = True

        # Send initial handshake
        await self.send({
            'type': 'agent_hello',
            'version': self.version,
            'hostname': os.uname().nodename,
            'platform': sys.platform
        })

        self.logger.info("Connected to CLI Pal service", always=True)

    async def _message_loop(self) -> None:
        """Handle incoming messages"""
        try:
            async for message in self.ws:
                try:
                    data = json.loads(message)
                    await self._handle_message(data)
                except json.JSONDecodeError:
                    self.logger.error(f"Invalid JSON: {message[:100]}")
                except Exception as e:
                    self.logger.error(f"Error handling message: {e}")
        except Exception as e:
            self.logger.debug(f"Message loop error: {e}")

    async def _handle_message(self, data: dict) -> None:
        """Route messages to appropriate handlers

        Args:
            data: Parsed message dict
        """
        msg_type = data.get('type')

        if msg_type == 'start_shell':
            await self.terminal.start_shell(
                data.get('cols', 80),
                data.get('rows', 24)
            )
        elif msg_type == 'command':
            await self.terminal.write_to_shell(data.get('data', ''))
        elif msg_type == 'resize':
            await self.terminal.resize(
                data.get('cols', 80),
                data.get('rows', 24)
            )
        elif msg_type == 'ping':
            await self.send({'type': 'pong'})
        else:
            self.logger.debug(f"Unknown message type: {msg_type}")

    async def send(self, data: dict) -> None:
        """Send JSON message to server

        Args:
            data: Message dict to send
        """
        if self.ws and self.connected:
            try:
                await self.ws.send(json.dumps(data))
            except Exception as e:
                self.logger.error(f"Error sending message: {e}")

    async def send_output(self, output: str) -> None:
        """Send terminal output to server

        Args:
            output: Terminal output string
        """
        await self.send({'type': 'output', 'data': output})

    def stop(self) -> None:
        """Stop the WebSocket client"""
        self.running = False
        if self.terminal:
            self.terminal.close()
