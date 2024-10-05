#!/usr/bin/env python3

import subprocess
import logging
import json
import asyncio
import httpx
import signal
from datetime import datetime
from typing import Optional, Dict, Any, Set

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Configuration variables
relays = ["wss://relay.primal.net"]
WEBHOOK_URL = "http://127.0.0.1:8090/cyber_herd"
HEX_KEY = ""
TAGS = ["CyberHerd"]
API_KEY = ""
config = {
    'ENDPOINT_URL': "http://127.0.0.1:8090/messages/cyberherd_treats"
}

http_client = httpx.AsyncClient(http2=True, limits=httpx.Limits(max_keepalive_connections=10, max_connections=20))


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
            response = await http_client.post(url, headers={"Content-Type": "application/json"}, json={"data": bolt11})
            response.raise_for_status()
            data = response.json()
            logger.debug(f"Bolt11 decode: {data}")
            return data
        except httpx.RequestError as e:
            logger.error(f"Failed to decode bolt11: {e}")
            return None


class Verifier:
    @staticmethod
    async def validate_lud16(lud16: str) -> bool:
        """Validate a LUD-16 Lightning Address."""
        user_domain = lud16.split('@')
        if len(user_domain) != 2:
            logger.error(f"Invalid LUD-16 format: {lud16}")
            return False
        user, domain = user_domain
        url = f'https://{domain}/.well-known/lnurlp/{user}'

        try:
            response = await http_client.get(url)
            response.raise_for_status()
            data = response.json()
            logger.debug(f"LUD-16 validation response: {data}")

            if data.get('status') == 'ERROR':
                logger.error(f"LUD-16 validation error status: {data}")
                return False
            if 'callback' in data and 'maxSendable' in data and 'minSendable' in data:
                return True

            logger.warning(f"LUD-16 validation missing parameters: {data}")
        except (httpx.RequestError, httpx.HTTPStatusError, ValueError) as e:
            logger.error(f"Failed to validate LUD-16: {e}")
        return False

    @staticmethod
    def verify_nip05(nip05: str) -> bool:
        """Verify a NIP-05 identifier using nak decode."""
        decode_command = ['/usr/local/bin/nak', 'decode', nip05]
        try:
            decode_result = subprocess.run(decode_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
            decoded_data = json.loads(decode_result.stdout)
            return True if decoded_data.get('pubkey') else False
        except subprocess.CalledProcessError as e:
            logger.error(f"Error decoding nip05: {e}")
        except json.JSONDecodeError as e:
            logger.error(f"Error parsing decoded nip05: {e}")
        return False


class EventProcessor:
    def __init__(self):
        self.seen_ids = set()
        self.json_objects = []

    async def send_json_payload(self, json_objects: list, webhook_url: str) -> bool:
        """Send JSON payload to the specified webhook URL."""
        if json_objects:
            try:
                logger.debug(f"Sending JSON payload: {json_objects}")
                response = await http_client.post(webhook_url, json=json_objects, timeout=10)
                response.raise_for_status()
                logger.info(f"Data sent successfully. Response: {response.text}")
                self.json_objects.clear()  # Clear the list after successful send
                return True
            except httpx.HTTPStatusError as e:
                logger.error(f"HTTP error occurred: {e.response.status_code} - {e.response.text}")
            except httpx.RequestError as e:
                logger.error(f"Request error occurred: {e}")
        else:
            logger.warning("No JSON objects to send.")
        return False


    def lookup_metadata(self, pubkey: str) -> Optional[Dict[str, Optional[str]]]:
        """Lookup metadata for the given pubkey."""
        logger.debug(f"Looking up metadata for pubkey: {pubkey}")
        metadata_command = ['/usr/local/bin/nak', 'req', '-k', '0', '-a', pubkey] + relays
        try:
            metadata_result = subprocess.run(metadata_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)

            last_meta_data = None

            for meta_line in metadata_result.stdout.splitlines():
                meta_data = json.loads(meta_line)
                content = json.loads(meta_data.get('content', '{}'))
                if content.get('lud16'):
                    if (last_meta_data is None) or (meta_data['created_at'] > last_meta_data['created_at']):
                        last_meta_data = meta_data

            if last_meta_data:
                content = json.loads(last_meta_data.get('content', '{}'))
                return {
                    'nip05': content.get('nip05', None),
                    'lud16': content.get('lud16', None),
                    'display_name': content.get('display_name', content.get('name', 'Anon'))
                }
            else:
                logger.warning(f"No metadata found for pubkey: {pubkey}")

        except (subprocess.CalledProcessError, json.JSONDecodeError) as e:
            logger.error(f"Failed to get or parse metadata for pubkey {pubkey}: {e}")

        return None

    async def handle_event(self, data: Dict[str, Any]) -> None:
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
            metadata = self.lookup_metadata(pubkey)
            if metadata:
                lud16 = metadata['lud16']
                display_name = metadata['display_name']

                if lud16:
                    nprofile_command = ['/usr/local/bin/nak', 'encode', 'nprofile', pubkey]
                    try:
                        nprofile_result = subprocess.run(nprofile_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
                        nprofile = nprofile_result.stdout.strip()
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
                            "notified": 'False',           #str 
                            "payouts": payouts              # float
                        }

                        self.json_objects.append(json_object)
                        logger.debug(f"Appending json object: {json_object}")
                        await self.send_json_payload(self.json_objects, WEBHOOK_URL)

                    except subprocess.CalledProcessError as e:
                        logger.error(f"Failed to encode nprofile for pubkey {pubkey}: {e}")
                else:
                    logger.warning(f"Missing lud16 for pubkey {pubkey}. Skipping event.")
            else:
                logger.warning(f"No metadata found for pubkey {pubkey}. Skipping event.")
        else:
            logger.debug(f"Pubkey matches HEX_KEY ({HEX_KEY}), skipping event.")

class Monitor:
    def __init__(self, event_processor: EventProcessor):
        self.event_processor = event_processor
        self.active_subprocesses: Set[asyncio.subprocess.Process] = set()
        self.shutdown_event = asyncio.Event()

    async def execute_subprocess(self, id_output: str, created_at_output: str) -> None:
        """Execute a subprocess to process events asynchronously."""
        command = f"/usr/local/bin/nak req --stream -k 6 -k 9735 -e {id_output} --since {created_at_output} " + ' '.join(relays)
        proc = await asyncio.create_subprocess_shell(command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        self.active_subprocesses.add(proc)
        logger.info(f"Subprocess started with PID: {proc.pid}")

        try:
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
        finally:
            self.active_subprocesses.discard(proc)

    async def monitor_new_notes(self) -> None:
        """Monitor events and process them asynchronously."""
        midnight_today = Utils.calculate_midnight()  # Calculate timestamp for midnight today

        tag_string = " ".join(f"-t t={tag}" for tag in TAGS)
        command = f"/usr/local/bin/nak req --stream -k 1 {tag_string} -a {HEX_KEY} --since {midnight_today} " + ' '.join(relays)
        proc = await asyncio.create_subprocess_shell(command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        self.active_subprocesses.add(proc)
        logger.info(f"Monitoring subprocess started with PID: {proc.pid}")

        try:
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

                        asyncio.create_task(self.execute_subprocess(id_output, created_at_output))

                except json.JSONDecodeError as e:
                    logger.error(f"Failed to parse JSON line: {line.strip()}, error: {e}")
                except Exception as e:
                    logger.error(f"Unexpected error while monitoring notes: {e}")

            await proc.wait()
            logger.info(f"Monitoring subprocess {proc.pid} terminated.")
        finally:
            self.active_subprocesses.discard(proc)

    async def shutdown(self):
        """Shutdown all subprocesses and set the shutdown event."""
        logger.info("Shutting down monitor...")
        self.shutdown_event.set()
        for proc in list(self.active_subprocesses):
            logger.info(f"Terminating subprocess {proc.pid}")
            proc.terminate()
            await proc.wait()
            self.active_subprocesses.discard(proc)
        logger.info("Monitor shutdown complete.")


async def main():
    event_processor = EventProcessor()
    monitor = Monitor(event_processor)

    loop = asyncio.get_running_loop()

    # Signal handler for graceful shutdown
    stop_event = asyncio.Event()

    def _signal_handler():
        logger.info("Shutdown signal received.")
        stop_event.set()

    loop.add_signal_handler(signal.SIGINT, _signal_handler)
    loop.add_signal_handler(signal.SIGTERM, _signal_handler)

    try:
        notes_task = asyncio.create_task(monitor.monitor_new_notes())
        await stop_event.wait()  # Wait until a shutdown signal is received
    finally:
        await monitor.shutdown()
        await http_client.aclose()
        logger.info("Service stopped gracefully.")


if __name__ == "__main__":
    asyncio.run(main())
