import json
import os
import threading
import time

try:
    import psutil
except Exception:
    psutil = None

HEARTBEAT_FILE = os.environ.get("JSCANNER_HEARTBEAT", "Result/heartbeat.json")
UDP_TARGET = os.environ.get("JSCANNER_HEARTBEAT_UDP", "")        # 形如 "127.0.0.1:19999"，空则不发
INTERVAL = float(os.environ.get("JSCANNER_HEARTBEAT_INTERVAL", "10"))


class _Heartbeat:
    def __init__(self):
        self._lock = threading.Lock()
        self._seq = 0
        self._last_beat = time.time()      # 最后一次“真进展”时间——判活核心
        self._phase = "init"
        self._detail = ""
        self._start = time.time()
        self._stop = threading.Event()
        self._thread = None
        self._proc = psutil.Process() if psutil else None

    def beat(self, phase: str = "", detail: str = ""):
        """喂狗：只做赋值，绝不阻塞。由真正干活的循环高频调用。"""
        with self._lock:
            self._seq += 1
            self._last_beat = time.time()
            if phase:
                self._phase = phase
            if detail:
                self._detail = str(detail)[:160]

    def _snapshot(self) -> dict:
        with self._lock:
            rss = 0.0
            if self._proc is not None:
                try:
                    rss = round(self._proc.memory_info().rss / 1048576, 1)
                except Exception:
                    rss = 0.0
            return {
                "seq": self._seq,
                "last_beat_epoch": round(self._last_beat, 3),
                "phase": self._phase,
                "detail": self._detail,
                "pid": os.getpid(),
                "rss_mb": rss,
                "uptime_s": round(time.time() - self._start, 1),
                "wall_epoch": round(time.time(), 3),
            }

    def _emit(self, data: dict):
        try:
            os.makedirs(os.path.dirname(HEARTBEAT_FILE) or ".", exist_ok=True)
            tmp = HEARTBEAT_FILE + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False)
            os.replace(tmp, HEARTBEAT_FILE)
        except Exception:
            pass
        if UDP_TARGET:
            try:
                import socket
                host, port = UDP_TARGET.rsplit(":", 1)
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.sendto(json.dumps(data).encode("utf-8"), (host, int(port)))
                s.close()
            except Exception:
                pass

    def _loop(self):
        # 卡死时线程仍在广播，但 last_beat_epoch 被冻结 → 外部据此判“停滞”
        while not self._stop.is_set():
            try:
                self._emit(self._snapshot())
            except Exception:
                pass
            self._stop.wait(INTERVAL)

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._emit(self._snapshot())
        self._thread = threading.Thread(target=self._loop, daemon=True, name="heartbeat")
        self._thread.start()


heartbeat = _Heartbeat()
beat = heartbeat.beat
start = heartbeat.start
