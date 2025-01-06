#!/usr/bin/env python3

import subprocess
import logging
import json
import asyncio
import httpx
import signal
from datetime import datetime
from typing import Optional, Dict, Any, Set

from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type

from cyberherd_module import (
    run_subprocess,
    Verifier,
    MetadataFetcher,
    generate_nprofile,
)

# -----------------------------------
# Configuration Variables
# -----------------------------------

# Toggle NIP-05 Verification
ENABLE_NIP05_VERIFICATION = True  # Set to False to disable NIP-05 verification

# Other Configuration Variables
relays = ["wss://relay.damus.io/" "wss://relay.primal.net/" "wss://relay.nostr.band/"]
WEBHOOK_URL = "http://127.0.0.1:8090/cyber_herd"
HEX_KEY = "669ebbcccf409ee0467a33660ae88fd17e5379e646e41d7c236ff4963f3c36b6"
TAGS = ["#CyberHerd", "CyberHerd"]  # some clients append the #
API_KEY = "036ad4bb0dcb4b8c952230ab7b47ea52"
config = {
    'ENDPOINT_URL': "http://127.0.0.1:8090/messages/cyberherd_treats"
}

# Concurrency Control Constants
MAX_CONCURRENT_SUBPROCESSES = 10  # Maximum number of concurrent subprocesses
MAX_CONCURRENT_HTTP_REQUESTS = 20  # Maximum number of concurrent HTTP requests

# Initialize Semaphores for Concurrency Control
subprocess_semaphore = asyncio.Semaphore(MAX_CONCURRENT_SUBPROCESSES)
http_semaphore = asyncio.Semaphore(MAX_CONCURRENT_HTTP_REQUESTS)

# Initialize the HTTP Client with Connection Limits
http_client = httpx.AsyncClient(
    http2=True,
    limits=httpx.Limits(max_keepalive_connections=10, max_connections=20)
)

# -----------------------------------
# Logging Configuration
# -----------------------------------

logging.basicConfig(level=logging.INFO, format='%(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# -----------------------------------
# Utility Class
# -----------------------------------

class Utils:
    @staticmethod
    def calculate_midnight() -> int:
        """Calculate the timestamp for the current day's midnight."""
        now = datetime.now()
        midnight = datetime.combine(now.date(), datetime.min.time())
        return int(midnight.timestamp())

    @staticmethod
    async def decode_bolt11(bolt11: str) -> Optional[Dict[str, Any]]:
        """Decode bolt11 field using lnbits API."""
        url = 'https://lnb.bolverker.com/api/v1/payments/decode'
        try:
            async with http_semaphore:
                response = await send_with_retry(
                    http_client.post,
                    url,
                    headers={"Content-Type": "application/json"},
                    json={"data": bolt11}
                )
            data = response.json()
            logger.debug(f"Bolt11 decode: {data}")
            return data
        except httpx.RequestError as e:
            logger.error(f"Failed to decode bolt11: {e}")
            return None
        except httpx.HTTPStatusError as e:
            logger.error(f"HTTP error during bolt11 decode: {e}")
            return None

# -----------------------------------
# Event Processor Class
# -----------------------------------

class EventProcessor:
    def __init__(self, subprocess_semaphore: asyncio.Semaphore, http_semaphore: asyncio.Semaphore):
        self.seen_ids = set()
        self.json_objects = []
        self.subprocess_semaphore = subprocess_semaphore
        self.http_semaphore = http_semaphore

        # Use the MetadataFetcher from cyberherd_module
        self.metadata_fetcher = MetadataFetcher()

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        retry=retry_if_exception_type(httpx.RequestError) | retry_if_exception_type(httpx.HTTPStatusError),
        reraise=True
    )
    async def send_json_payload(self, json_objects: list, webhook_url: str) -> bool:
        """Send JSON payload to the specified webhook URL with retry logic."""
        if json_objects:
            try:
                async with self.http_semaphore:
                    logger.debug(f"Sending JSON payload: {json_objects}")
                    response = await http_client.post(webhook_url, json=json_objects, timeout=10)
                response.raise_for_status()
                logger.info(f"Data sent successfully. Response: {response.text}")
                self.json_objects.clear()  # Clear the list after successful send
                return True
            except (httpx.HTTPStatusError, httpx.RequestError) as e:
                logger.error(f"HTTP error occurred: {e}")
                raise  # Propagate exception to trigger retry
        else:
            logger.warning("No JSON objects to send.")
        return False

    async def handle_event(self, data: Dict[str, Any]) -> None:
        """
        Handle individual events based on their kind.
        Only kind 6 (Repost) logic is retained.
        """
        try:
            event_id = data.get('cyberherd_id')
            note = data.get('id')
            pubkey = data.get('pubkey')
            kind = data.get('kind')
            amount = data.get('amount', 0)

            if note in self.seen_ids:
                logger.debug(f"Skipping already processed event: {note}")
                return

            self.seen_ids.add(note)

            if not pubkey or kind is None:
                logger.error(f"Event data missing 'pubkey' or 'kind': {data}")
                return

            logger.info(f"Handling event: event_id={note}, pubkey={pubkey}, kind={kind}, amount={amount}")

            # Only process kind 6; all other kinds are ignored
            if kind != 6:
                logger.debug(f"Kind is not 6; ignoring event {note}.")
                return

            # Skip if pubkey is the configured HEX_KEY
            if pubkey == HEX_KEY:
                logger.debug(f"Pubkey matches HEX_KEY ({HEX_KEY}), skipping event.")
                return

            # Fetch metadata via the MetadataFetcher
            metadata = await self.metadata_fetcher.lookup_metadata(pubkey)
            if not metadata:
                logger.warning(f"No metadata found for pubkey {pubkey}. Skipping event.")
                return

            lud16 = metadata.get('lud16')
            nip05 = metadata.get('nip05')
            display_name = metadata.get('display_name', 'Anon')

            # If NIP-05 verification is enabled and nip05 is present, verify it
            if ENABLE_NIP05_VERIFICATION and nip05:
                nip05 = nip05.lower().strip()
                logger.debug(f"Processed NIP-05: '{nip05}'")
                is_valid_nip05 = await Verifier.verify_nip05(nip05, pubkey)
                if not is_valid_nip05:
                    logger.error(f"Invalid NIP-05 identifier for pubkey {pubkey}: {nip05}")
                    return  # Skip processing this event due to invalid NIP-05
                else:
                    logger.info(f"Valid NIP-05 identifier for pubkey {pubkey}: {nip05}")
            else:
                logger.debug("Skipping NIP-05 verification.")

            # If lud16 is present, generate nprofile
            if not lud16:
                logger.warning(f"Missing lud16 for pubkey {pubkey}. Skipping event.")
                return

            try:
                nprofile = await generate_nprofile(pubkey)
                if not nprofile:
                    logger.error(f"Failed to generate nprofile for pubkey: {pubkey}")
                    return

                logger.debug(f"Metadata lookup success: {metadata}")

                # For kind 6, set amount to 0, set default payouts
                amount = 0
                payouts = 0.1

                json_object = {
                    "display_name": display_name,
                    "event_id": event_id,
                    "note": note,
                    "kinds": [kind],
                    "pubkey": pubkey,
                    "nprofile": nprofile,
                    "lud16": lud16,
                    "notified": 'False',
                    "payouts": payouts
                }

                self.json_objects.append(json_object)
                logger.debug(f"Appending json object: {json_object}")
                await self.send_json_payload(self.json_objects, WEBHOOK_URL)

            except asyncio.TimeoutError as e:
                logger.error(f"Nprofile encoding timed out: {e}")
            except Exception as e:
                logger.error(f"Unexpected error during nprofile encoding: {e}")

        except Exception as e:
            logger.error(f"Unexpected error in handle_event: {e}")

# -----------------------------------
# Monitor Class
# -----------------------------------

class Monitor:
    def __init__(self, event_processor: EventProcessor, subprocess_semaphore: asyncio.Semaphore):
        self.event_processor = event_processor
        self.active_subprocesses: Set[asyncio.subprocess.Process] = set()
        self.shutdown_event = asyncio.Event()
        self.subprocess_semaphore = subprocess_semaphore

    async def execute_subprocess(self, id_output: str, created_at_output: str) -> None:
        """
        Execute a subprocess to process events asynchronously.
        Only kind 6 (Repost) logic is handled.
        """
        command = (
            f"/usr/local/bin/nak req --stream -k 6 -e {id_output} "
            f"--since {created_at_output} "
            "wss://relay.damus.io wss://relay.artx.market/ wss://relay.primal.net/ ws://127.0.0.1:3002/nostrrelay/666"
        )
        logger.debug(f"Executing subprocess command: {command}")
        async with self.subprocess_semaphore:
            try:
                proc = await asyncio.create_subprocess_shell(
                    command,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                self.active_subprocesses.add(proc)
                logger.info(f"Subprocess started with PID: {proc.pid}")

                async for line in proc.stdout:
                    if self.shutdown_event.is_set():
                        logger.info(f"Shutdown signal received. Terminating subprocess {proc.pid}")
                        proc.terminate()
                        break
                    try:
                        data = json.loads(line)
                        data['cyberherd_id'] = id_output
                        pubkey = data.get('pubkey')
                        note = data.get('id')

                        # Only handle kind 6
                        if data.get('kind') == 6:
                            logger.debug(f"Processing Repost event, ID: {note}")
                            await self.event_processor.handle_event(data)

                    except json.JSONDecodeError as e:
                        logger.error(f"Failed to parse JSON line: {line.strip()}, error: {e}")
                    except Exception as e:
                        logger.error(f"Unexpected error while processing line: {line.strip()}, error: {e}")

                await proc.wait()
                logger.info(f"Subprocess {proc.pid} terminated.")
            except Exception as e:
                logger.error(f"Error executing subprocess: {e}")
            finally:
                self.active_subprocesses.discard(proc)

    async def monitor_new_notes(self) -> None:
        """
        Monitor events and process them asynchronously.
        Focuses on any new notes that have #CyberHerd or CyberHerd tags,
        then spawns subprocesses to fetch kind 6 events.
        """
        midnight_today = Utils.calculate_midnight()  # Calculate timestamp for midnight today

        tag_string = " ".join(f"-t t={tag}" for tag in TAGS)
        command = (
            f"/usr/local/bin/nak req --stream -k 1 {tag_string} -a {HEX_KEY} "
            f"--since {midnight_today} "
            "wss://relay.damus.io wss://relay.artx.market/ wss://relay.primal.net/ ws://127.0.0.1:3002/nostrrelay/666"
        )
        logger.debug(f"Monitoring subprocess command: {command}")
        async with self.subprocess_semaphore:
            try:
                proc = await asyncio.create_subprocess_shell(
                    command,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                self.active_subprocesses.add(proc)
                logger.info(f"Monitoring subprocess started with PID: {proc.pid}")

                async for line in proc.stdout:
                    if self.shutdown_event.is_set():
                        logger.info(f"Shutdown signal received. Terminating monitoring subprocess {proc.pid}")
                        proc.terminate()
                        break
                    try:
                        data = json.loads(line)
                        id_output = data.get('id')
                        created_at_output = data.get('created_at')

                        # If this note is new, spawn a subprocess to fetch kind 6 events
                        if id_output and created_at_output and id_output not in self.event_processor.seen_ids:
                            logger.debug(f"New note detected: {id_output}")
                            self.event_processor.seen_ids.add(id_output)

                            # Ensure that exceptions in execute_subprocess do not propagate
                            task = asyncio.create_task(self.execute_subprocess(id_output, created_at_output))
                            task.add_done_callback(
                                lambda t: logger.error(f"Subprocess task error: {t.exception()}") if t.exception() else None
                            )

                    except json.JSONDecodeError as e:
                        logger.error(f"Failed to parse JSON line: {line.strip()}, error: {e}")
                    except Exception as e:
                        logger.error(f"Unexpected error while monitoring notes: {e}")

                await proc.wait()
                logger.info(f"Monitoring subprocess {proc.pid} terminated.")
            except Exception as e:
                logger.error(f"Error in monitor_new_notes: {e}")
            finally:
                self.active_subprocesses.discard(proc)

    async def shutdown(self):
        """Shutdown all subprocesses and set the shutdown event."""
        logger.info("Shutting down monitor...")
        self.shutdown_event.set()
        async with self.subprocess_semaphore:
            for proc in list(self.active_subprocesses):
                logger.info(f"Terminating subprocess {proc.pid}")
                proc.terminate()
                await proc.wait()
                self.active_subprocesses.discard(proc)
        logger.info("Monitor shutdown complete.")

# -----------------------------------
# Helper Functions
# -----------------------------------

@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=2, max=10),
    retry=retry_if_exception_type(httpx.RequestError) | retry_if_exception_type(httpx.HTTPStatusError),
    reraise=True
)
async def send_with_retry(func, *args, **kwargs):
    """Helper function to send HTTP requests with retry logic."""
    async with http_semaphore:
        try:
            response = await func(*args, **kwargs)
            response.raise_for_status()
            return response
        except (httpx.RequestError, httpx.HTTPStatusError) as e:
            logger.error(f"HTTP request failed: {e}")
            raise

# -----------------------------------
# Main Function
# -----------------------------------

async def main():
    event_processor = EventProcessor(subprocess_semaphore, http_semaphore)
    monitor = Monitor(event_processor, subprocess_semaphore)

    loop = asyncio.get_running_loop()

    # Signal handler for graceful shutdown
    stop_event = asyncio.Event()

    def _signal_handler():
        logger.info("Shutdown signal received.")
        stop_event.set()

    try:
        loop.add_signal_handler(signal.SIGINT, _signal_handler)
        loop.add_signal_handler(signal.SIGTERM, _signal_handler)
    except NotImplementedError:
        # Signal handling might not be implemented on some platforms (e.g., Windows)
        logger.warning("Signal handlers are not implemented on this platform.")

    try:
        notes_task = asyncio.create_task(monitor.monitor_new_notes())
        await stop_event.wait()  # Wait until a shutdown signal is received
    finally:
        await monitor.shutdown()
        await http_client.aclose()
        logger.info("Service stopped gracefully.")

# -----------------------------------
# Entry Point
# -----------------------------------

if __name__ == "__main__":
    asyncio.run(main())
