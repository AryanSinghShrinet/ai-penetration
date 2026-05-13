"""
Vulnerability Database Updater

Orchestrates syncing from multiple sources:
- NVD (NIST National Vulnerability Database)
- ExploitDB (Offensive Security)
- Local exploit database

Features:
- Scheduled and manual updates
- Incremental sync based on last update time
- Progress tracking and logging
"""

import logging
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, Optional, Callable, List
from datetime import datetime, timedelta
from pathlib import Path

from core.vuln_database import VulnDatabase, CVERecord, ExploitRecord, get_vuln_database
from core.nvd_client import NVDClient, get_nvd_client
from core.exploitdb_client import ExploitDBClient, get_exploitdb_client
from core.exploit_db import EXPLOIT_DATABASE, Exploit


# Configure logging
logger = logging.getLogger("vuln_updater")

# Also log to file
_log_dir = Path(__file__).parent.parent / "data" / "logs"
_log_dir.mkdir(parents=True, exist_ok=True)
_file_handler = logging.FileHandler(_log_dir / "vuln_updater.log")
_file_handler.setLevel(logging.INFO)
_file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
logger.addHandler(_file_handler)


@dataclass
class SyncProgress:
    """Tracks sync progress."""
    source: str
    status: str = "pending"  # pending, running, completed, error
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    items_fetched: int = 0
    items_inserted: int = 0
    errors: int = 0
    message: str = ""


@dataclass
class SyncResult:
    """Result of a sync operation."""
    success: bool
    sources: Dict[str, SyncProgress] = field(default_factory=dict)
    total_cves: int = 0
    total_exploits: int = 0
    duration_seconds: float = 0
    error_message: Optional[str] = None


class VulnUpdater:
    """
    Vulnerability database updater.
    
    Syncs from NVD and ExploitDB to local SQLite database.
    """
    
    def __init__(
        self,
        db: VulnDatabase = None,
        nvd_api_key: str = None
    ):
        """
        Initialize the updater.
        
        Args:
            db: VulnDatabase instance (creates new if None)
            nvd_api_key: Optional NVD API key for faster rate limits
        """
        self.db = db or get_vuln_database()
        self.nvd_client = get_nvd_client(nvd_api_key)
        self.exploitdb_client = get_exploitdb_client()
        
        self._sync_lock = threading.Lock()
        self._is_syncing = False
        self._current_progress: Dict[str, SyncProgress] = {}
        self._progress_callback: Optional[Callable] = None
    
    def set_progress_callback(self, callback: Callable[[Dict[str, SyncProgress]], None]):
        """Set callback for progress updates."""
        self._progress_callback = callback
    
    def _update_progress(self, source: str, **kwargs):
        """Update progress and notify callback."""
        if source not in self._current_progress:
            self._current_progress[source] = SyncProgress(source=source)
        
        progress = self._current_progress[source]
        for key, value in kwargs.items():
            if hasattr(progress, key):
                setattr(progress, key, value)
        
        if self._progress_callback:
            try:
                self._progress_callback(self._current_progress)
            except Exception as e:
                logger.warning(f"Progress callback error: {e}")
    
    def is_syncing(self) -> bool:
        """Check if sync is in progress."""
        return self._is_syncing
    
    def get_progress(self) -> Dict[str, SyncProgress]:
        """Get current sync progress."""
        return self._current_progress.copy()
    
    # =========================================================================
    # Sync Methods
    # =========================================================================
    
    def sync_all(
        self,
        incremental: bool = True,
        days: int = 30,
        max_nvd_cves: int = 5000,
        max_exploitdb: int = None
    ) -> SyncResult:
        """
        Sync from all sources.
        
        Args:
            incremental: Use incremental sync based on last update
            days: Days to look back if not incremental
            max_nvd_cves: Maximum NVD CVEs to fetch
            max_exploitdb: Maximum ExploitDB entries (None for all)
            
        Returns:
            SyncResult with statistics
        """
        # S-7 FIX: check-and-set under the lock to eliminate TOCTOU race.
        # Two simultaneous POST /sync requests can both pass is_syncing()==False
        # before either one sets _is_syncing. Acquiring the lock first prevents this.
        with self._sync_lock:
            if self._is_syncing:
                return SyncResult(
                    success=False,
                    error_message="Sync already in progress"
                )
            self._is_syncing = True
            self._current_progress = {}
            start_time = time.time()
            result = SyncResult(success=True)
            
            try:
                # Sync local exploits first (fast)
                logger.info("Syncing local exploits...")
                local_result = self.sync_local_exploits()
                result.sources["local"] = local_result
                
                # Sync NVD
                logger.info("Syncing NVD CVEs...")
                nvd_result = self.sync_nvd(
                    incremental=incremental,
                    days=days,
                    max_results=max_nvd_cves
                )
                result.sources["nvd"] = nvd_result
                result.total_cves = nvd_result.items_inserted
                
                # Sync ExploitDB
                logger.info("Syncing ExploitDB...")
                edb_result = self.sync_exploitdb(max_exploits=max_exploitdb)
                result.sources["exploitdb"] = edb_result
                result.total_exploits = (
                    local_result.items_inserted + edb_result.items_inserted
                )
                
            except Exception as e:
                logger.error(f"Sync failed: {e}")
                result.success = False
                result.error_message = str(e)
            
            finally:
                self._is_syncing = False
                result.duration_seconds = time.time() - start_time
                logger.info(f"Sync complete in {result.duration_seconds:.1f}s")
        
        return result
    
    def sync_nvd(
        self,
        incremental: bool = True,
        days: int = 30,
        max_results: int = 5000
    ) -> SyncProgress:
        """
        Sync CVEs from NVD.
        
        Args:
            incremental: Fetch only new/modified CVEs since last sync
            days: Days to look back if not incremental
            max_results: Maximum CVEs to fetch
            
        Returns:
            SyncProgress with statistics
        """
        progress = SyncProgress(
            source="nvd",
            status="running",
            started_at=datetime.utcnow().isoformat()
        )
        self._current_progress["nvd"] = progress
        
        try:
            self._update_progress("nvd", message="Starting NVD sync...")
            
            stats = self.nvd_client.sync_to_database(
                db=self.db,
                incremental=incremental,
                days=days,
                max_results=max_results
            )
            
            progress.items_fetched = stats.get("fetched", 0)
            progress.items_inserted = stats.get("inserted", 0)
            progress.errors = stats.get("errors", 0)
            progress.status = "completed"
            progress.completed_at = datetime.utcnow().isoformat()
            progress.message = f"Synced {progress.items_inserted} CVEs"
            
            logger.info(f"NVD sync: {stats}")
            
        except Exception as e:
            logger.error(f"NVD sync error: {e}")
            progress.status = "error"
            progress.message = str(e)
        
        self._current_progress["nvd"] = progress
        return progress
    
    def sync_exploitdb(
        self,
        max_exploits: int = None,
        verified_only: bool = False
    ) -> SyncProgress:
        """
        Sync exploits from ExploitDB.
        
        Args:
            max_exploits: Maximum exploits to sync
            verified_only: Only sync verified exploits
            
        Returns:
            SyncProgress with statistics
        """
        progress = SyncProgress(
            source="exploitdb",
            status="running",
            started_at=datetime.utcnow().isoformat()
        )
        self._current_progress["exploitdb"] = progress
        
        try:
            self._update_progress("exploitdb", message="Downloading ExploitDB data...")
            
            stats = self.exploitdb_client.sync_to_database(
                db=self.db,
                max_exploits=max_exploits,
                verified_only=verified_only
            )
            
            progress.items_fetched = stats.get("fetched", 0)
            progress.items_inserted = stats.get("inserted", 0)
            progress.errors = stats.get("errors", 0)
            progress.status = "completed"
            progress.completed_at = datetime.utcnow().isoformat()
            progress.message = f"Synced {progress.items_inserted} exploits"
            
            logger.info(f"ExploitDB sync: {stats}")
            
        except Exception as e:
            logger.error(f"ExploitDB sync error: {e}")
            progress.status = "error"
            progress.message = str(e)
        
        self._current_progress["exploitdb"] = progress
        return progress
    
    def sync_local_exploits(self) -> SyncProgress:
        """
        Sync exploits from local exploit_db.py database.
        
        Returns:
            SyncProgress with statistics
        """
        progress = SyncProgress(
            source="local",
            status="running",
            started_at=datetime.utcnow().isoformat()
        )
        self._current_progress["local"] = progress
        
        try:
            # Convert local exploits to ExploitRecord format
            exploits = []
            for exp in EXPLOIT_DATABASE:
                record = ExploitRecord(
                    id=exp.id,
                    title=exp.name,
                    description=exp.description,
                    platform=exp.platform.value,
                    exploit_type=exp.exploit_type.value,
                    payload=exp.payload if exp.payload else None,
                    cve_id=exp.cve_id,
                    source="local",
                    source_id=exp.exploitdb_id,
                    reference_url=exp.reference_urls[0] if exp.reference_urls else None,
                    verified=exp.reliability == "high",
                    keywords=exp.detection_patterns,
                    affected_products=exp.affected_versions
                )
                exploits.append(record)
            
            progress.items_fetched = len(exploits)
            inserted = self.db.bulk_upsert_exploits(exploits)
            
            progress.items_inserted = inserted
            progress.errors = len(exploits) - inserted
            progress.status = "completed"
            progress.completed_at = datetime.utcnow().isoformat()
            progress.message = f"Synced {inserted} local exploits"
            
            logger.info(f"Local exploit sync: {inserted}/{len(exploits)}")
            
        except Exception as e:
            logger.error(f"Local sync error: {e}")
            progress.status = "error"
            progress.message = str(e)
        
        self._current_progress["local"] = progress
        return progress


# =========================================================================
# Background Scheduler
# =========================================================================

class VulnUpdateScheduler:
    """
    Background scheduler for automatic updates.
    """
    
    def __init__(
        self,
        updater: VulnUpdater,
        interval_hours: int = 24
    ):
        """
        Initialize scheduler.
        
        Args:
            updater: VulnUpdater instance
            interval_hours: Hours between updates
        """
        self.updater = updater
        self.interval = interval_hours * 3600
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._last_update: Optional[datetime] = None
    
    def start(self):
        """Start the background scheduler."""
        if self._thread and self._thread.is_alive():
            logger.warning("Scheduler already running")
            return
        
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        logger.info(f"Update scheduler started (interval: {self.interval/3600:.1f}h)")
    
    def stop(self):
        """Stop the background scheduler."""
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)
        logger.info("Update scheduler stopped")
    
    def _run(self):
        """Background scheduler loop."""
        while not self._stop_event.is_set():
            # Check if update is needed
            should_update = False
            
            if self._last_update is None:
                should_update = True
            else:
                elapsed = (datetime.utcnow() - self._last_update).total_seconds()
                if elapsed >= self.interval:
                    should_update = True
            
            if should_update:
                logger.info("Running scheduled update...")
                try:
                    result = self.updater.sync_all(incremental=True)
                    self._last_update = datetime.utcnow()
                    logger.info(f"Scheduled update complete: {result.total_cves} CVEs, {result.total_exploits} exploits")
                except Exception as e:
                    logger.error(f"Scheduled update failed: {e}")
            
            # Sleep with interruption check
            self._stop_event.wait(timeout=60)  # Check every minute


# Convenience functions
def get_vuln_updater(nvd_api_key: str = None) -> VulnUpdater:
    """Get a VulnUpdater instance."""
    return VulnUpdater(nvd_api_key=nvd_api_key)


def sync_vulnerability_database(
    nvd_api_key: str = None,
    incremental: bool = True,
    days: int = 30
) -> SyncResult:
    """
    Convenience function to sync the vulnerability database.
    
    Args:
        nvd_api_key: Optional NVD API key
        incremental: Use incremental sync
        days: Days to look back
        
    Returns:
        SyncResult
    """
    updater = get_vuln_updater(nvd_api_key)
    return updater.sync_all(incremental=incremental, days=days)


if __name__ == "__main__":
    # Test the updater
    logging.basicConfig(level=logging.INFO)
    
    print("Testing VulnUpdater...")
    
    updater = VulnUpdater()
    
    # Sync local exploits only (fast test)
    print("\nSyncing local exploits...")
    result = updater.sync_local_exploits()
    print(f"  Status: {result.status}")
    print(f"  Inserted: {result.items_inserted}")
    
    # Show database stats
    print("\nDatabase stats:")
    stats = updater.db.get_stats()
    print(f"  Total CVEs: {stats['total_cves']}")
    print(f"  Total exploits: {stats['total_exploits']}")
    print(f"  Exploits with CVE: {stats['exploits_with_cve']}")
    print(f"  Exploits without CVE: {stats['exploits_without_cve']}")
    
    print("\nVulnUpdater test complete!")
