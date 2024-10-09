#!/usr/bin/env python3
import asyncio
import websockets
import json
import logging
import os
import httpx
from typing import Dict, Any
from dataclasses import dataclass
from asyncio import Task
from tenacity import (
    retry,
    stop_after_attempt,
    wait_exponential,
    retry_if_exception_type,
    before_sleep_log,
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@dataclass
class Config:
    WS_CYBERHERD: str
    ENDPOINT_URL: str
    IGNORE_NPUBS: list[str]

def load_config() -> Config:
    return Config(
        WS_CYBERHERD=os.getenv(
            'WS_CYBERHERD',
            "ws://127.0.0.1:3002/api/v1/ws/39f4aed2967d492884446e8c7aa734af"
        ),
        ENDPOINT_URL="http://127.0.0.1:8090/messages/cyberherd_treats",
        IGNORE_NPUBS=["Bolverker", "Unknown"]
    )

config = load_config()

class WebSocketClient:
    def __init__(self, uri: str, identifier: str):
        self.uri = uri
        self.identifier = identifier
        self.websocket = None
        self.http_client = httpx.AsyncClient(
            http2=True,
            limits=httpx.Limits(max_keepalive_connections=10)
        )
        self.reconnect_task: Task | None = None
        self.heartbeat_task: Task | None = None
        self.heartbeat_interval = 30  # seconds between heartbeats
        self.heartbeat_timeout = 10   # seconds to wait for pong

    @retry(
        retry=retry_if_exception_type((
            websockets.ConnectionClosed,
            websockets.InvalidURI,
            websockets.WebSocketProtocolError,
            OSError
        )),
        wait=wait_exponential(min=1, max=60),
        stop=stop_after_attempt(None),  # Retry indefinitely
        before_sleep=before_sleep_log(logger, logging.WARNING)
    )
    async def connect(self):
        logger.info(f"Attempting to connect to WebSocket ({self.identifier}): {self.uri}")
        self.websocket = await websockets.connect(
            self.uri,
            ping_interval=None  # Disable built-in ping to implement custom heartbeat
        )
        logger.info(f"Connected to WebSocket ({self.identifier}): {self.uri}")

    @retry(
        retry=retry_if_exception_type(httpx.HTTPError),
        wait=wait_exponential(min=1, max=60),
        stop=stop_after_attempt(5),  # Retry up to 5 times
        before_sleep=before_sleep_log(logger, logging.WARNING)
    )
    async def send_to_endpoint(self, pubkey: str, amount: float):
        payload = {"pubkey": pubkey, "amount": amount}
        try:
            response = await self.http_client.post(
                config.ENDPOINT_URL,
                json=payload,
                timeout=10.0
            )
            response.raise_for_status()
            logger.info(f"Sent to endpoint: {payload}")
        except httpx.HTTPError as exc:
            logger.error(f"Error sending to endpoint: {exc}")
            raise  # Re-raise to trigger Tenacity retry

    def extract_pubkey(self, memo: str) -> str | None:
        words = memo.split()
        if len(words) > 0 and words[-1] not in config.IGNORE_NPUBS:
            return words[-1]
        return None

    async def process_cyberherd_message(self, data: Dict[str, Any]):
        if "payment" in data and data["payment"].get("amount", 0) < 0:
            amount = abs(data["payment"]["amount"]) / 1000
            memo = data["payment"]["memo"]
            pubkey = self.extract_pubkey(memo)
            if pubkey:
                await self.send_to_endpoint(pubkey, amount)

    async def send_heartbeat(self):
        """
        Periodically send ping frames to the WebSocket server to ensure the connection is alive.
        """
        try:
            while True:
                await asyncio.sleep(self.heartbeat_interval)
                if self.websocket:
                    logger.debug(f"Sending heartbeat ping ({self.identifier})")
                    ping_future = asyncio.create_task(self.websocket.ping())
                    try:
                        await asyncio.wait_for(ping_future, timeout=self.heartbeat_timeout)
                        logger.debug(f"Heartbeat pong received ({self.identifier})")
                    except asyncio.TimeoutError:
                        logger.warning(f"No pong received within {self.heartbeat_timeout} seconds ({self.identifier}). Reconnecting...")
                        await self.websocket.close()
                        break
        except asyncio.CancelledError:
            logger.info(f"Heartbeat task cancelled ({self.identifier}).")
        except Exception as e:
            logger.error(f"Heartbeat encountered an error ({self.identifier}): {e}")

    async def process_messages(self):
        while True:
            try:
                message = await self.websocket.recv()
                data = json.loads(message)
                
                if self.identifier == 'cyberherd':
                    await self.process_cyberherd_message(data)
            except websockets.ConnectionClosed:
                logger.warning(f"WebSocket connection closed ({self.identifier}). Reconnecting...")
                break
            except json.JSONDecodeError:
                logger.error(f"Failed to decode JSON message ({self.identifier})")
            except Exception as e:
                logger.error(f"Error processing message ({self.identifier}): {e}")

    async def run(self):
        while True:
            try:
                await self.connect()
                # Start heartbeat task
                self.heartbeat_task = asyncio.create_task(self.send_heartbeat())
                # Start processing messages
                await self.process_messages()
            except Exception as e:
                logger.error(f"Unexpected error in run loop ({self.identifier}): {e}")
            finally:
                # Cancel heartbeat task if it's running
                if self.heartbeat_task and not self.heartbeat_task.done():
                    self.heartbeat_task.cancel()
                    try:
                        await self.heartbeat_task
                    except asyncio.CancelledError:
                        logger.info(f"Heartbeat task cancelled during cleanup ({self.identifier}).")
                # Close websocket if it's still open
                if self.websocket and not self.websocket.closed:
                    await self.websocket.close()
                logger.info(f"Reconnecting to WebSocket ({self.identifier}) after error...")

    async def start(self):
        self.reconnect_task = asyncio.create_task(self.run())

    async def stop(self):
        if self.reconnect_task:
            self.reconnect_task.cancel()
            try:
                await self.reconnect_task
            except asyncio.CancelledError:
                logger.info(f"Reconnect task cancelled ({self.identifier}).")
        if self.heartbeat_task:
            self.heartbeat_task.cancel()
            try:
                await self.heartbeat_task
            except asyncio.CancelledError:
                logger.info(f"Heartbeat task cancelled during stop ({self.identifier}).")
        if self.websocket and not self.websocket.closed:
            await self.websocket.close()
            logger.info(f"WebSocket connection closed ({self.identifier}).")
        await self.http_client.aclose()
        logger.info(f"HTTP client closed ({self.identifier}).")

async def main():
    client = WebSocketClient(config.WS_CYBERHERD, 'cyberherd')

    await client.start()

    try:
        await asyncio.gather(*(client.reconnect_task,))
    except asyncio.CancelledError:
        logger.info("Main task cancelled. Shutting down...")
    finally:
        await client.stop()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("WebSocket listener stopped.")
