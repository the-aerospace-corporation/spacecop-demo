import os
import sys
import time
import zlib
import logging
from openc3.microservices.microservice import Microservice
from openc3.utilities.sleeper import Sleeper
from openc3.api import *

RECEIVED_DIR = "/openc3/lib/openc3/operators/received_files"
SEND_DIR = "/openc3/lib/openc3/operators/send_files"

# Bytes of file data per chunk. MUST equal FSW CFDP_DATA_CHUNK_SIZE
# (apps/cfdp/fsw/src/cfdp_cfdp.h). Used to compute each chunk's file offset.
CHUNK = 1024

# Class 2 (acknowledged) retransmit tuning.
MAX_NAK_ROUNDS = 5      # give up after this many NAK passes
NAK_TIMEOUT = 3.0       # seconds to wait for resends before re-NAKing
NAK_INTER_CMD = 0.05    # pacing between individual RESEND commands
DONE_TTL = 30.0         # ignore stray resends for a completed file this long


class CFDP(Microservice):
    def __init__(self, name):
        super().__init__(name)
        self.TARGET_NAME = "CFDP"
        self.TLM_PACKET_NAME = "DOWNLINK_FILE_PKT"
        self.CMD_PACKET_NAME = "UPLOAD_TO_SATELLITE_DATA"
        self.RESEND_CMD = "RESEND_CHUNK"
        self.period = 2
        self.sleeper = Sleeper()
        self.CHUNK_SIZE = 256  # upload read size (unchanged)

        # Active downloads, keyed by destination filename:
        #   {received:set(seq), total:int|None, src:str, bytes:int,
        #    nak_deadline:float, nak_round:int}
        self.xfers = {}
        # Recently completed files -> expiry time, to swallow stray late resends.
        self.done = {}

        self.log = logging.getLogger("CFDP_MICROSERVICE")
        self.log.setLevel(logging.DEBUG)
        self.log.propagate = False
        handler = logging.StreamHandler(sys.stdout)
        handler.setLevel(logging.DEBUG)
        handler.setFormatter(logging.Formatter("CFDP_MICROSERVICE %(asctime)s %(levelname)s: %(message)s"))
        self.log.handlers.clear()
        self.log.addHandler(handler)

        self._hb = 0
        self._last_err = None

        self.log.info("CFDP microservice starting (Class 2 / NAK retransmit)")
        print("CFDP_MICROSERVICE stdout alive", flush=True)

    def _err_once(self, where, e):
        key = f"{where}:{type(e).__name__}:{e}"
        if key != self._last_err:
            self.log.error(f"{where}: {type(e).__name__}: {e}")
            self._last_err = key

    # ------------------------------------------------------------------ main
    def run(self):
        self.sleeper.sleep(self.period)
        while True:
            if self.cancel_thread:
                break

            try:
                pdu = tlm(f"{self.TARGET_NAME} {self.TLM_PACKET_NAME} PDU_TYPE")
                direction = tlm(f"{self.TARGET_NAME} {self.TLM_PACKET_NAME} DIRECTION")
                filename_dst = tlm(f"{self.TARGET_NAME} {self.TLM_PACKET_NAME} FILENAME_DST")
                filename_src = tlm(f"{self.TARGET_NAME} {self.TLM_PACKET_NAME} FILENAME_SRC")
            except Exception as e:
                self._err_once("poll", e)
                self.sleeper.sleep(0.05)
                continue

            if filename_dst is not None and filename_src is not None:
                filename_dst = filename_dst.strip()
                filename_src = filename_src.strip()

                self._hb += 1
                if self._hb % 100 == 0:
                    self.log.info(f"heartbeat: pdu={pdu} direction={direction} dst={filename_dst!r}")

                self._expire_done()

                # Swallow stray late resends for a file we already finished.
                if filename_dst in self.done and not (direction == 1 and pdu != 2 and self._is_seq_zero()):
                    self._ack()
                elif direction == 1 and pdu != 2:
                    self._on_data_chunk(filename_dst, filename_src)
                elif direction == 1 and pdu == 2:
                    self._on_eof(filename_dst, filename_src)
                elif direction == 2:
                    self._upload_file(filename_dst, filename_src)
                    self._ack()

            # Time-driven retransmit: re-NAK any transfer whose wait expired.
            self._service_nak_timers()

            self.sleeper.sleep(0.05)

    # --------------------------------------------------------------- helpers
    def _ack(self):
        """Consume the latched packet so it is not reprocessed."""
        try:
            set_tlm(f"{self.TARGET_NAME} {self.TLM_PACKET_NAME} DIRECTION = 99")
        except Exception as e:
            self._err_once("ack", e)

    def _is_seq_zero(self):
        try:
            return tlm(f"{self.TARGET_NAME} {self.TLM_PACKET_NAME} SEQ_NUM") == 0
        except Exception:
            return False

    def _expire_done(self):
        now = time.time()
        for d in [k for k, exp in self.done.items() if exp <= now]:
            del self.done[d]

    def _start_xfer(self, dst, src):
        # Fresh download: truncate/create the file so offset writes are clean.
        open(os.path.join(RECEIVED_DIR, dst), "wb").close()
        self.xfers[dst] = {
            "received": set(), "total": None, "src": src, "bytes": 0,
            "nak_deadline": time.time() + NAK_TIMEOUT, "nak_round": 0,
        }
        self.done.pop(dst, None)

    def _write_at(self, dst, offset, data):
        path = os.path.join(RECEIVED_DIR, dst)
        with open(path, "r+b") as f:
            f.seek(offset)
            f.write(data)

    # ------------------------------------------------------------ data chunk
    def _on_data_chunk(self, dst, src):
        try:
            seq = tlm(f"{self.TARGET_NAME} {self.TLM_PACKET_NAME} SEQ_NUM")
        except Exception as e:
            self._err_once("write:SEQ_NUM", e)
            return

        # A seq-0 chunk for a finished file means a NEW download of that name.
        if dst in self.done and seq == 0:
            self.done.pop(dst, None)

        if dst not in self.xfers:
            self._start_xfer(dst, src)
        x = self.xfers[dst]

        if seq in x["received"]:
            return  # dedup: latched packet re-read, or duplicate resend

        try:
            data = tlm(f"{self.TARGET_NAME} {self.TLM_PACKET_NAME} FILE_DATA")
            n = tlm(f"{self.TARGET_NAME} {self.TLM_PACKET_NAME} DATA_LEN")
            if tlm(f"{self.TARGET_NAME} {self.TLM_PACKET_NAME} SEQ_NUM") != seq:
                return  # packet updated mid-read; catch it next poll
        except Exception as e:
            self._err_once("write:FILE_DATA/DATA_LEN", e)
            return

        if data is None:
            return
        if isinstance(data, str):
            data = data.encode("latin-1")
        elif isinstance(data, (bytes, bytearray)):
            data = bytes(data)
        else:
            self._err_once("write:FILE_DATA type",
                           TypeError(f"FILE_DATA is {type(data).__name__}, not bytes "
                                     f"(FSW packet size likely != COSMOS def)"))
            return

        chunk = data[:n] if n else data
        self._write_at(dst, seq * CHUNK, chunk)
        x["received"].add(seq)
        x["bytes"] += len(chunk)
        if not x["src"]:
            x["src"] = src

        # Completion can happen mid-stream once total (from EOF) is known.
        self._maybe_complete(dst)

    # -------------------------------------------------------------------- EOF
    def _on_eof(self, dst, src):
        try:
            total = tlm(f"{self.TARGET_NAME} {self.TLM_PACKET_NAME} SEQ_NUM")
        except Exception as e:
            self._err_once("eof:SEQ_NUM", e)
            self._ack()
            return

        if dst not in self.xfers:
            # EOF with no data received yet - set up so we can NAK everything.
            self._start_xfer(dst, src)
        x = self.xfers[dst]
        x["total"] = total
        if not x["src"]:
            x["src"] = src

        self._service_naks(dst)
        # Consume the EOF; further retransmit is driven by the NAK timer.
        self._ack()

    # ------------------------------------------------------------ retransmit
    def _service_naks(self, dst):
        x = self.xfers.get(dst)
        if not x or x["total"] is None:
            return
        missing = set(range(x["total"])) - x["received"]
        if not missing:
            self._finalize(dst, True)
            return
        if x["nak_round"] >= MAX_NAK_ROUNDS:
            self._finalize(dst, False)
            return

        x["nak_round"] += 1
        self.log.info(f"NAK round {x['nak_round']} for {dst}: requesting {len(missing)} "
                      f"missing chunk(s) of {x['total']}")
        src = x["src"]
        for seq in sorted(missing):
            try:
                cmd(f"{self.TARGET_NAME} {self.RESEND_CMD} with "
                    f"SEQ_NUM {seq}, SOURCE '{src}', DESTINATION '{dst}'")
            except Exception as e:
                self._err_once("nak:cmd", e)
            time.sleep(NAK_INTER_CMD)
        x["nak_deadline"] = time.time() + NAK_TIMEOUT

    def _service_nak_timers(self):
        now = time.time()
        for dst in list(self.xfers.keys()):
            x = self.xfers.get(dst)
            if x and x["total"] is not None and now >= x["nak_deadline"]:
                self._service_naks(dst)

    def _maybe_complete(self, dst):
        x = self.xfers.get(dst)
        if x and x["total"] is not None and len(x["received"]) >= x["total"]:
            self._finalize(dst, True)

    def _finalize(self, dst, complete):
        x = self.xfers.pop(dst, None)
        if x is None:
            return
        try:
            size = os.path.getsize(os.path.join(RECEIVED_DIR, dst))
        except OSError:
            size = x["bytes"]
        if complete:
            self.log.info(f"File {dst} COMPLETE: {x['total']} chunk(s), {size} bytes "
                          f"({x['nak_round']} NAK round(s))")
        else:
            missing = x["total"] - len(x["received"]) if x["total"] else "?"
            self.log.warning(f"File {dst} INCOMPLETE after {MAX_NAK_ROUNDS} NAK rounds: "
                             f"{missing} chunk(s) still missing, {size} bytes")
        self.done[dst] = time.time() + DONE_TTL
        self._ack()

    # ----------------------------------------------------------------- upload
    def _upload_file(self, filename_dst, filename_src):
        self.log.info(f"Uploading {filename_dst} -> SC:{filename_src}")
        src_path = os.path.join(SEND_DIR, filename_dst)

        # Pre-compute integrity values so the EOF can carry them for the FSW to
        # verify against the received file (size catches dropped chunks / short
        # file; CRC-32 catches reordering/corruption).
        try:
            with open(src_path, "rb") as f:
                contents = f.read()
        except FileNotFoundError:
            self.log.error(f"Upload failed: {src_path} not found")
            return
        exp_size = len(contents)
        exp_crc = zlib.crc32(contents) & 0xFFFFFFFF

        seq = 0
        for off in range(0, exp_size, self.CHUNK_SIZE):
            data = contents[off:off + self.CHUNK_SIZE]
            hex_data = data.hex()
            # Data chunks carry 0/0 for the integrity fields.
            cmd(f"{self.TARGET_NAME} {self.CMD_PACKET_NAME} with "
                f"LENGTH {len(hex_data)}, PDU 1, DESTINATION '{filename_src}', "
                f"FILE_DATA '{hex_data}', EXPECTED_SIZE 0, EXPECTED_CRC 0")
            self.log.info(f"upload seq {seq}: sent {len(data)} bytes")
            seq += 1
            time.sleep(5)

        # EOF carries the expected size + CRC-32 for FSW-side verification.
        cmd(f"{self.TARGET_NAME} {self.CMD_PACKET_NAME} with "
            f"LENGTH 0, PDU 2, DESTINATION '{filename_src}', FILE_DATA '', "
            f"EXPECTED_SIZE {exp_size}, EXPECTED_CRC {exp_crc}")
        self.log.info(f"File {filename_dst} upload complete ({seq} chunk(s), "
                      f"{exp_size} bytes, crc 0x{exp_crc:08X}) - awaiting FSW verify")

    def shutdown(self):
        self.sleeper.cancel()
        super().shutdown()


if __name__ == "__main__":
    print("CFDP_MICROSERVICE STARTING", flush=True)
    CFDP("DEFAULT__MICROSERVICE__CFDP").run()
