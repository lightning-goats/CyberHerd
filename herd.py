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

# -----------------------------------
# Configuration Variables
# -----------------------------------

# Toggle NIP-05 Verification
ENABLE_NIP05_VERIFICATION = False  # Set to False to disable NIP-05 verification

# Other Configuration Variables
relays = ["ws://127.0.0.1:3002/nostrclient/api/v1/relay"]
WEBHOOK_URL = "http://127.0.0.1:8090/cyber_herd"
HEX_KEY = ""
TAGS = ["#CyberHerd", "CyberHerd"]  #some clients append the #
API_KEY = ""
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
# Utility Functions
# -----------------------------------

async def run_subprocess(command: list, timeout: int = 30) -> subprocess.CompletedProcess:
    """Run a subprocess asynchronously with a timeout."""
    proc = await asyncio.create_subprocess_exec(
        *command,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return subprocess.CompletedProcess(args=command, returncode=proc.returncode, stdout=stdout, stderr=stderr)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.communicate()
        raise asyncio.TimeoutError(f"Subprocess '{' '.join(command)}' timed out after {timeout} seconds.")

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
# Verifier Class
# -----------------------------------

class Verifier:
    @staticmethod
    async def verify_nip05(nip05: str, expected_pubkey: str) -> bool:
        """
        Asynchronously verify a NIP-05 identifier using nak decode subprocess.
        """
        if not ENABLE_NIP05_VERIFICATION:
            logger.debug("NIP-05 verification is disabled. Skipping verification.")
            return True  # If verification is disabled, consider it as valid

        if not nip05:
            logger.error("No NIP-05 identifier provided.")
            return False

        nip05 = nip05.lower().strip()
        logger.debug(f"Verifying NIP-05: '{nip05}' for pubkey: {expected_pubkey}")

        decode_command = ['/usr/local/bin/nak', 'decode', nip05]
        logger.debug(f"Running command: {' '.join(decode_command)}")

        async with subprocess_semaphore:
            try:
                result = await run_subprocess(decode_command, timeout=10)
                if result.returncode != 0:
                    stderr_output = result.stderr.decode().strip()
                    logger.error(f"Error decoding NIP-05: {stderr_output}")
                    return False

                decoded_data = json.loads(result.stdout.decode())
                decoded_pubkey = decoded_data.get('pubkey')

                if not decoded_pubkey:
                    logger.error(f"No pubkey found in decoded NIP-05 data: {decoded_data}")
                    return False

                if decoded_pubkey != expected_pubkey:
                    logger.error(f"Pubkey mismatch: expected {expected_pubkey}, got {decoded_pubkey}")
                    return False

                logger.debug(f"NIP-05 decoded successfully: {decoded_data}")
                return True

            except asyncio.TimeoutError as e:
                logger.error(f"NIP-05 verification timed out: {e}")
            except json.JSONDecodeError as e:
                logger.error(f"Error parsing decoded NIP-05 data: {e}")
            except Exception as e:
                logger.error(f"Unexpected error during NIP-05 verification: {e}")

            return False

# -----------------------------------
# Event Processor Class
# -----------------------------------

class EventProcessor:
    def __init__(self, subprocess_semaphore: asyncio.Semaphore, http_semaphore: asyncio.Semaphore):
        self.seen_ids = set()
        self.json_objects = []
        self.subprocess_semaphore = subprocess_semaphore
        self.http_semaphore = http_semaphore

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

    async def lookup_metadata(self, pubkey: str) -> Optional[Dict[str, Optional[str]]]:
        """Asynchronously lookup metadata for the given pubkey."""
        logger.debug(f"Looking up metadata for pubkey: {pubkey}")
        metadata_command = ['/usr/local/bin/nak', 'req', '-k', '0', '-a', pubkey] + relays
        async with self.subprocess_semaphore:
            try:
                result = await run_subprocess(metadata_command, timeout=15)
                if result.returncode != 0:
                    logger.error(f"Error fetching metadata: {result.stderr.decode().strip()}")
                    return None

                last_meta_data = None

                for meta_line in result.stdout.decode().splitlines():
                    try:
                        meta_data = json.loads(meta_line)
                        content = json.loads(meta_data.get('content', '{}'))
                        if content.get('lud16'):
                            if (last_meta_data is None) or (meta_data['created_at'] > last_meta_data['created_at']):
                                last_meta_data = meta_data
                    except json.JSONDecodeError as e:
                        logger.error(f"Error parsing metadata line: {e}")

                if last_meta_data:
                    content = json.loads(last_meta_data.get('content', '{}'))
                    return {
                        'nip05': content.get('nip05', None),
                        'lud16': content.get('lud16', None),
                        'display_name': content.get('display_name', content.get('name', 'Anon'))
                    }
                else:
                    logger.warning(f"No metadata found for pubkey: {pubkey}")

            except asyncio.TimeoutError:
                logger.error("Timeout while fetching metadata.")
            except Exception as e:
                logger.error(f"Unexpected error during metadata lookup: {e}")

            return None

    async def handle_event(self, data: Dict[str, Any]) -> None:
        """Handle individual events based on their type and metadata."""
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

            if pubkey != HEX_KEY:
                metadata = await self.lookup_metadata(pubkey)
                if metadata:
                    lud16 = metadata['lud16']
                    nip05 = metadata.get('nip05')  # Retrieve nip05 from metadata
                    display_name = metadata['display_name']

                    if nip05:
                        nip05 = nip05.lower().strip()  # Convert to lowercase and strip
                        logger.debug(f"Processed NIP-05: '{nip05}'")
                    else:
                        logger.warning(f"No NIP-05 identifier found for pubkey {pubkey}. Skipping processing.")
                        return

                    if lud16:
                        # Verify NIP-05 if it exists
                        is_valid_nip05 = await Verifier.verify_nip05(nip05, pubkey)
                        if not is_valid_nip05:
                            logger.error(f"Invalid NIP-05 identifier for pubkey {pubkey}: {nip05}")
                            return  # Skip processing this event due to invalid NIP-05
                        else:
                            logger.info(f"Valid NIP-05 identifier for pubkey {pubkey}: {nip05}")

                        # Encode nprofile using subprocess
                        nprofile_command = ['/usr/local/bin/nak', 'encode', 'nprofile', pubkey]
                        async with self.subprocess_semaphore:
                            try:
                                result = await run_subprocess(nprofile_command, timeout=10)
                                if result.returncode != 0:
                                    logger.error(f"Error encoding nprofile: {result.stderr.decode().strip()}")
                                    return

                                nprofile = result.stdout.decode().strip()
                                logger.debug(f"Metadata lookup success: {metadata}")

                                # Adjust kind and payouts based on event type
                                if kind == 9734:
                                    kind = 9735
                                if kind == 6:
                                    amount = 0  # Reposts might not have an amount
                                    payouts = 0.1  # Default payout for kind 6
                                else:
                                    payouts = min(amount / 100, 1.0) if amount else 0.0

                                json_object = {
                                    "display_name": display_name,  # Optional[str]
                                    "event_id": event_id,          # str
                                    "note": note,                  # str
                                    "kinds": [kind],               # List[int]
                                    "pubkey": pubkey,              # str
                                    "nprofile": nprofile,          # str
                                    "lud16": lud16,                # str
                                    "notified": 'False',           # str 
                                    "payouts": payouts              # float
                                }

                                self.json_objects.append(json_object)
                                logger.debug(f"Appending json object: {json_object}")
                                await self.send_json_payload(self.json_objects, WEBHOOK_URL)

                            except asyncio.TimeoutError as e:
                                logger.error(f"Nprofile encoding timed out: {e}")
                            except Exception as e:
                                logger.error(f"Unexpected error during nprofile encoding: {e}")
                    else:
                        logger.warning(f"Missing lud16 for pubkey {pubkey}. Skipping event.")
                else:
                    logger.warning(f"No metadata found for pubkey {pubkey}. Skipping event.")
            else:
                logger.debug(f"Pubkey matches HEX_KEY ({HEX_KEY}), skipping event.")

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
        """Execute a subprocess to process events asynchronously."""
        command = f"/usr/local/bin/nak req --stream -k 6 -e {id_output} --since {created_at_output} " + ' '.join(relays)
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

                        if pubkey:
                            if data.get('kind') == 6:
                                logger.debug(f"Processing Repost event, ID: {note}")
                                await self.event_processor.handle_event(data)  # Pass event data to handle_event
                            elif data.get('kind') == 9735:
                                logger.debug(f"Processing Zap event, ID: {note}")
                                bolt11 = None
                                description_data = None
                                for tag in data.get('tags', []):
                                    if tag[0] == 'bolt11':
                                        bolt11 = tag[1]
                                    elif tag[0] == 'description':
                                        try:
                                            description_data = json.loads(tag[1])
                                        except json.JSONDecodeError as e:
                                            logger.error(f"Failed to parse description JSON: {e}")
                                            continue

                                if bolt11 and description_data:
                                    decoded_data = await Utils.decode_bolt11(bolt11)

                                    if decoded_data and 'amount_msat' in decoded_data:
                                        amount_sat = decoded_data['amount_msat'] / 1000  # Convert msat to sat
                                        description_data['amount'] = amount_sat
                                        description_data['kind'] = 9735  # Ensure kind is set
                                        if amount_sat >= 10:
                                            await self.event_processor.handle_event(description_data)
                                        else:
                                            logger.info(f"Amount too small: {amount_sat} sats")
                                    else:
                                        logger.error("Decoded data missing 'amount_msat'")
                                else:
                                    logger.error("Missing bolt11 or description_data in Zap event")
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
        """Monitor events and process them asynchronously."""
        midnight_today = Utils.calculate_midnight()  # Calculate timestamp for midnight today

        tag_string = " ".join(f"-t t={tag}" for tag in TAGS)
        command = f"/usr/local/bin/nak req --stream -k 1 {tag_string} -a {HEX_KEY} --since {midnight_today} " + ' '.join(relays)
        logger.debug(f"Monitoring subprocess command: {command}")
        async with self.subprocess_semaphore:
            try:
                proc = await asyncio.create_subprocess_shell(command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
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
