import threading
import time
from typing import Callable

class LogoutHandler:
    """Manages automatic session timeout."""

    def __init__(self, timeout_seconds: int, logout_callback: Callable[[bool], None]) -> None:
        """
        :param timeout_seconds: Number of seconds before automatic logout.
        :param logout_callback: Function to call when timeout occurs. 
                                Passed True if automatic timeout, False if manual.
        """
        self.timeout_seconds = timeout_seconds
        self.logout_callback = logout_callback
        self.timer_thread: threading.Thread | None = None
        self.stop_event = threading.Event()
        self.is_running = False

    def start(self) -> None:
        """Start the timeout timer."""
        self.cancel()  # Ensure any existing timer is stopped
        self.stop_event.clear()
        self.is_running = True
        self.timer_thread = threading.Thread(target=self._run_timer, daemon=True)
        self.timer_thread.start()

    def cancel(self) -> None:
        """Cancel the timeout timer (e.g., on manual logout)."""
        if self.is_running:
            self.stop_event.set()
            self.is_running = False
            if self.timer_thread and self.timer_thread.is_alive():
                self.timer_thread.join(timeout=1.0)

    def _run_timer(self) -> None:
        """Wait for the timeout, then trigger logout if not cancelled."""
        elapsed = 0
        while elapsed < self.timeout_seconds and not self.stop_event.is_set():
            time.sleep(1)
            elapsed += 1
            
        if not self.stop_event.is_set():
            # Time is up and not cancelled, trigger automatic logout
            self.is_running = False
            self.logout_callback(True)  # True indicates automatic timeout
