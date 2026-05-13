"""
Vulnerability Database for AI-Pentester

SQLite-based persistent storage for CVEs and exploits with:
- Full-text search capability
- CVSS v2 and v3 support with normalized severity
- CPE matching for product identification
- Efficient indexing for fast lookups
"""

import sqlite3
import json
import logging
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Tuple, Any
from pathlib import Path
from datetime import datetime
from enum import Enum


# Configure logging
logger = logging.getLogger("vuln_database")

try:
    import psycopg2
    from psycopg2.extras import RealDictCursor
except ImportError:
    psycopg2 = None
    RealDictCursor = None


class Severity(Enum):
    """Normalized severity levels."""
    NONE = "NONE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class CVERecord:
    """CVE vulnerability record."""
    id: str
    description: str
    cvss_v3_score: Optional[float] = None
    cvss_v3_vector: Optional[str] = None
    cvss_v2_score: Optional[float] = None
    cvss_v2_vector: Optional[str] = None
    published_date: Optional[str] = None
    modified_date: Optional[str] = None
    cwe_ids: List[str] = field(default_factory=list)
    affected_products: List[str] = field(default_factory=list)  # CPE strings
    references: List[str] = field(default_factory=list)
    source: str = "nvd"
    
    @property
    def severity(self) -> Severity:
        """Get normalized severity from CVSS v3 or v2."""
        # Prefer v3, fall back to v2
        score = self.cvss_v3_score if self.cvss_v3_score is not None else self.cvss_v2_score
        
        if score is None:
            return Severity.NONE
        elif score == 0.0:
            return Severity.NONE
        elif score < 4.0:
            return Severity.LOW
        elif score < 7.0:
            return Severity.MEDIUM
        elif score < 9.0:
            return Severity.HIGH
        else:
            return Severity.CRITICAL
    
    @property
    def best_cvss_score(self) -> Optional[float]:
        """Get the best available CVSS score (v3 preferred)."""
        return self.cvss_v3_score if self.cvss_v3_score is not None else self.cvss_v2_score


@dataclass
class ExploitRecord:
    """Exploit record that may or may not be linked to a CVE."""
    id: str
    title: str
    description: str
    platform: str
    exploit_type: str
    payload: Optional[str] = None
    cve_id: Optional[str] = None  # Can be NULL - not all exploits have CVEs
    source: str = "local"  # 'local', 'exploitdb', 'nuclei'
    source_id: Optional[str] = None  # EDB-ID, nuclei template name, etc.
    reference_url: Optional[str] = None
    author: Optional[str] = None
    published_date: Optional[str] = None
    verified: bool = False
    # Keywords for matching when no CVE is available
    keywords: List[str] = field(default_factory=list)
    affected_products: List[str] = field(default_factory=list)


class VulnDatabase:
    """
    SQLite-based vulnerability database.
    
    Features:
    - Persistent storage in data/exploits.db
    - Full-text search on descriptions
    - CVSS v2/v3 with normalized severity
    - CPE-based product matching
    - Efficient indexing
    """
    
    SCHEMA_VERSION = 1
    
    def __init__(self, db_path: str = None):
        """
        Initialize the vulnerability database.
        
        Args:
            db_path: Path to SQLite database. Defaults to data/exploits.db
        """
        if db_path is None:
            db_path = Path(__file__).parent.parent / "data" / "exploits.db"
        
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        
        self._conn: Optional[sqlite3.Connection] = None
        self._init_database()
    
    def _is_postgres(self):
        url = os.environ.get("DATABASE_URL")
        return url is not None and url.startswith("postgres") and psycopg2 is not None

    @property
    def conn(self) -> Any:
        """Get database connection (lazy initialization)."""
        if self._conn is None:
            if self._is_postgres():
                db_url = os.environ.get("DATABASE_URL")
                self._conn = psycopg2.connect(db_url)
                # Set autocommit to True for schema changes
                self._conn.autocommit = True
            else:
                self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
                self._conn.row_factory = sqlite3.Row
                # Enable foreign keys
                self._conn.execute("PRAGMA foreign_keys = ON")
        return self._conn
    
    def _get_cursor(self):
        if self._is_postgres():
            return self.conn.cursor(cursor_factory=RealDictCursor)
        return self.conn.cursor()

    def _init_database(self):
        """Initialize database schema."""
        cursor = self._get_cursor()
        
        # Check if we need to create/upgrade schema
        if self._is_postgres():
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT
                )
            """)
        else:
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT
                )
            """)
        
        cursor.execute("SELECT value FROM metadata WHERE key = 'schema_version'")
        row = cursor.fetchone()
        current_version = int(row['value'] if self._is_postgres() else (row['value'] if row else 0)) if row else 0
        
        if current_version < self.SCHEMA_VERSION:
            self._create_schema(cursor)
            if self._is_postgres():
                cursor.execute(
                    "INSERT INTO metadata (key, value) VALUES (%s, %s) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
                    ('schema_version', str(self.SCHEMA_VERSION))
                )
            else:
                cursor.execute(
                    "INSERT OR REPLACE INTO metadata (key, value) VALUES (?, ?)",
                    ('schema_version', str(self.SCHEMA_VERSION))
                )
            self.conn.commit()
        
        logger.info(f"VulnDatabase initialized (Postgres: {self._is_postgres()})")
    
    def _create_schema(self, cursor: Any):
        """Create database schema."""
        
        # CVE table with both CVSS v2 and v3
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS cves (
                id TEXT PRIMARY KEY,
                description TEXT,
                cvss_v3_score REAL,
                cvss_v3_vector TEXT,
                cvss_v2_score REAL,
                cvss_v2_vector TEXT,
                published_date TEXT,
                modified_date TEXT,
                cwe_ids TEXT,
                affected_products TEXT,
                references_json TEXT,
                source TEXT DEFAULT 'nvd',
                severity TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Exploits table - cve_id can be NULL
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS exploits (
                id TEXT PRIMARY KEY,
                cve_id TEXT,
                title TEXT NOT NULL,
                description TEXT,
                platform TEXT,
                exploit_type TEXT,
                payload TEXT,
                source TEXT DEFAULT 'local',
                source_id TEXT,
                reference_url TEXT,
                author TEXT,
                published_date TEXT,
                verified INTEGER DEFAULT 0,
                keywords TEXT,
                affected_products TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (cve_id) REFERENCES cves(id) ON DELETE SET NULL
            )
        """)
        
        # CPE matches table for product identification
        if self._is_postgres():
             cursor.execute("""
                CREATE TABLE IF NOT EXISTS cpe_matches (
                    id SERIAL PRIMARY KEY,
                    cve_id TEXT NOT NULL,
                    cpe_string TEXT NOT NULL,
                    vendor TEXT,
                    product TEXT,
                    version_start TEXT,
                    version_end TEXT,
                    vulnerable INTEGER DEFAULT 1,
                    FOREIGN KEY (cve_id) REFERENCES cves(id) ON DELETE CASCADE
                )
            """)
        else:
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS cpe_matches (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    cve_id TEXT NOT NULL,
                    cpe_string TEXT NOT NULL,
                    vendor TEXT,
                    product TEXT,
                    version_start TEXT,
                    version_end TEXT,
                    vulnerable INTEGER DEFAULT 1,
                    FOREIGN KEY (cve_id) REFERENCES cves(id) ON DELETE CASCADE
                )
            """)
        
        # Create indexes for fast lookups
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_cves_cvss_v3 ON cves(cvss_v3_score)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_cves_cvss_v2 ON cves(cvss_v2_score)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_cves_severity ON cves(severity)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_cves_published ON cves(published_date)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_cves_modified ON cves(modified_date)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_exploits_cve ON exploits(cve_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_exploits_platform ON exploits(platform)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_exploits_type ON exploits(exploit_type)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_exploits_source ON exploits(source)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_cpe_cve ON cpe_matches(cve_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_cpe_product ON cpe_matches(product)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_cpe_vendor ON cpe_matches(vendor)")
        
        if not self._is_postgres():
            # Full-text search virtual tables (SQLite only)
            cursor.execute("""
                CREATE VIRTUAL TABLE IF NOT EXISTS cves_fts USING fts5(
                    id, description, content='cves', content_rowid='rowid'
                )
            """)
            
            cursor.execute("""
                CREATE VIRTUAL TABLE IF NOT EXISTS exploits_fts USING fts5(
                    id, title, description, keywords, content='exploits', content_rowid='rowid'
                )
            """)
            
            # Triggers to keep FTS in sync
            cursor.executescript("""
                CREATE TRIGGER IF NOT EXISTS cves_ai AFTER INSERT ON cves BEGIN
                    INSERT INTO cves_fts(rowid, id, description) 
                    VALUES (NEW.rowid, NEW.id, NEW.description);
                END;
                
                CREATE TRIGGER IF NOT EXISTS cves_ad AFTER DELETE ON cves BEGIN
                    INSERT INTO cves_fts(cves_fts, rowid, id, description) 
                    VALUES('delete', OLD.rowid, OLD.id, OLD.description);
                END;
                
                CREATE TRIGGER IF NOT EXISTS cves_au AFTER UPDATE ON cves BEGIN
                    INSERT INTO cves_fts(cves_fts, rowid, id, description) 
                    VALUES('delete', OLD.rowid, OLD.id, OLD.description);
                    INSERT INTO cves_fts(rowid, id, description) 
                    VALUES (NEW.rowid, NEW.id, NEW.description);
                END;
                
                CREATE TRIGGER IF NOT EXISTS exploits_ai AFTER INSERT ON exploits BEGIN
                    INSERT INTO exploits_fts(rowid, id, title, description, keywords) 
                    VALUES (NEW.rowid, NEW.id, NEW.title, NEW.description, NEW.keywords);
                END;
                
                CREATE TRIGGER IF NOT EXISTS exploits_ad AFTER DELETE ON exploits BEGIN
                    INSERT INTO exploits_fts(exploits_fts, rowid, id, title, description, keywords) 
                    VALUES('delete', OLD.rowid, OLD.id, OLD.title, OLD.description, OLD.keywords);
                END;
                
                CREATE TRIGGER IF NOT EXISTS exploits_au AFTER UPDATE ON exploits BEGIN
                    INSERT INTO exploits_fts(exploits_fts, rowid, id, title, description, keywords) 
                    VALUES('delete', OLD.rowid, OLD.id, OLD.title, OLD.description, OLD.keywords);
                    INSERT INTO exploits_fts(rowid, id, title, description, keywords) 
                    VALUES (NEW.rowid, NEW.id, NEW.title, NEW.description, NEW.keywords);
                END;
            """)
        
        logger.info("Database schema created/updated")
        
        logger.info("Database schema created/updated")
    
    # =========================================================================
    # CVE Operations
    # =========================================================================
    
    def upsert_cve(self, cve: CVERecord) -> bool:
        """Insert or update a CVE record."""
        try:
            cursor = self._get_cursor()
            if self._is_postgres():
                cursor.execute("""
                    INSERT INTO cves (
                        id, description, cvss_v3_score, cvss_v3_vector,
                        cvss_v2_score, cvss_v2_vector, published_date, modified_date,
                        cwe_ids, affected_products, references_json, source, severity,
                        updated_at
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP)
                    ON CONFLICT (id) DO UPDATE SET
                        description = EXCLUDED.description,
                        cvss_v3_score = EXCLUDED.cvss_v3_score,
                        cvss_v3_vector = EXCLUDED.cvss_v3_vector,
                        cvss_v2_score = EXCLUDED.cvss_v2_score,
                        cvss_v2_vector = EXCLUDED.cvss_v2_vector,
                        modified_date = EXCLUDED.modified_date,
                        cwe_ids = EXCLUDED.cwe_ids,
                        affected_products = EXCLUDED.affected_products,
                        references_json = EXCLUDED.references_json,
                        severity = EXCLUDED.severity,
                        updated_at = CURRENT_TIMESTAMP
                """, (
                    cve.id, cve.description, cve.cvss_v3_score, cve.cvss_v3_vector,
                    cve.cvss_v2_score, cve.cvss_v2_vector, cve.published_date, cve.modified_date,
                    json.dumps(cve.cwe_ids), json.dumps(cve.affected_products),
                    json.dumps(cve.references), cve.source, cve.severity.value
                ))
            else:
                cursor.execute("""
                    INSERT OR REPLACE INTO cves (
                        id, description, cvss_v3_score, cvss_v3_vector,
                        cvss_v2_score, cvss_v2_vector, published_date, modified_date,
                        cwe_ids, affected_products, references_json, source, severity,
                        updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                """, (
                    cve.id, cve.description, cve.cvss_v3_score, cve.cvss_v3_vector,
                    cve.cvss_v2_score, cve.cvss_v2_vector, cve.published_date, cve.modified_date,
                    json.dumps(cve.cwe_ids), json.dumps(cve.affected_products),
                    json.dumps(cve.references), cve.source, cve.severity.value
                ))
            self.conn.commit()
            return True
        except Exception as e:
            logger.error(f"Failed to upsert CVE {cve.id}: {e}")
            return False
    
    def bulk_upsert_cves(self, cves: List[CVERecord]) -> int:
        """Bulk insert/update CVE records. Returns count of successful inserts."""
        success_count = 0
        cursor = self.conn.cursor()
        
        try:
            for cve in cves:
                try:
                    cursor.execute("""
                        INSERT OR REPLACE INTO cves (
                            id, description, cvss_v3_score, cvss_v3_vector,
                            cvss_v2_score, cvss_v2_vector, published_date, modified_date,
                            cwe_ids, affected_products, references_json, source, severity,
                            updated_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                    """, (
                        cve.id,
                        cve.description,
                        cve.cvss_v3_score,
                        cve.cvss_v3_vector,
                        cve.cvss_v2_score,
                        cve.cvss_v2_vector,
                        cve.published_date,
                        cve.modified_date,
                        json.dumps(cve.cwe_ids),
                        json.dumps(cve.affected_products),
                        json.dumps(cve.references),
                        cve.source,
                        cve.severity.value
                    ))
                    success_count += 1
                except Exception as e:
                    logger.warning(f"Failed to insert CVE {cve.id}: {e}")
            
            self.conn.commit()
        except Exception as e:
            logger.error(f"Bulk CVE insert failed: {e}")
            self.conn.rollback()
        
        return success_count
    
    def get_cve(self, cve_id: str) -> Optional[CVERecord]:
        """Get a CVE by ID."""
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM cves WHERE id = ?", (cve_id.upper(),))
        row = cursor.fetchone()
        
        if row:
            return self._row_to_cve(row)
        return None
    
    def _row_to_cve(self, row: sqlite3.Row) -> CVERecord:
        """Convert database row to CVERecord."""
        return CVERecord(
            id=row['id'],
            description=row['description'] or "",
            cvss_v3_score=row['cvss_v3_score'],
            cvss_v3_vector=row['cvss_v3_vector'],
            cvss_v2_score=row['cvss_v2_score'],
            cvss_v2_vector=row['cvss_v2_vector'],
            published_date=row['published_date'],
            modified_date=row['modified_date'],
            cwe_ids=json.loads(row['cwe_ids'] or '[]'),
            affected_products=json.loads(row['affected_products'] or '[]'),
            references=json.loads(row['references_json'] or '[]'),
            source=row['source'] or 'nvd'
        )
    
    # =========================================================================
    # Exploit Operations
    # =========================================================================
    
    def upsert_exploit(self, exploit: ExploitRecord) -> bool:
        """Insert or update an exploit record."""
        try:
            cursor = self._get_cursor()
            if self._is_postgres():
                cursor.execute("""
                    INSERT INTO exploits (
                        id, cve_id, title, description, platform, exploit_type,
                        payload, source, source_id, reference_url, author,
                        published_date, verified, keywords, affected_products,
                        updated_at
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP)
                    ON CONFLICT (id) DO UPDATE SET
                        cve_id = EXCLUDED.cve_id,
                        title = EXCLUDED.title,
                        description = EXCLUDED.description,
                        platform = EXCLUDED.platform,
                        exploit_type = EXCLUDED.exploit_type,
                        payload = EXCLUDED.payload,
                        source_id = EXCLUDED.source_id,
                        reference_url = EXCLUDED.reference_url,
                        author = EXCLUDED.author,
                        published_date = EXCLUDED.published_date,
                        verified = EXCLUDED.verified,
                        keywords = EXCLUDED.keywords,
                        affected_products = EXCLUDED.affected_products,
                        updated_at = CURRENT_TIMESTAMP
                """, (
                    exploit.id, exploit.cve_id, exploit.title, exploit.description,
                    exploit.platform, exploit.exploit_type, exploit.payload,
                    exploit.source, exploit.source_id, exploit.reference_url,
                    exploit.author, exploit.published_date, 1 if exploit.verified else 0,
                    json.dumps(exploit.keywords), json.dumps(exploit.affected_products)
                ))
            else:
                cursor.execute("""
                    INSERT OR REPLACE INTO exploits (
                        id, cve_id, title, description, platform, exploit_type,
                        payload, source, source_id, reference_url, author,
                        published_date, verified, keywords, affected_products,
                        updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                """, (
                    exploit.id, exploit.cve_id, exploit.title, exploit.description,
                    exploit.platform, exploit.exploit_type, exploit.payload,
                    exploit.source, exploit.source_id, exploit.reference_url,
                    exploit.author, exploit.published_date, 1 if exploit.verified else 0,
                    json.dumps(exploit.keywords), json.dumps(exploit.affected_products)
                ))
            self.conn.commit()
            return True
        except Exception as e:
            logger.error(f"Failed to upsert exploit {exploit.id}: {e}")
            return False
    
    def bulk_upsert_exploits(self, exploits: List[ExploitRecord]) -> int:
        """Bulk insert/update exploit records. Returns count of successful inserts."""
        success_count = 0
        cursor = self.conn.cursor()
        
        try:
            for exploit in exploits:
                try:
                    cursor.execute("""
                        INSERT OR REPLACE INTO exploits (
                            id, cve_id, title, description, platform, exploit_type,
                            payload, source, source_id, reference_url, author,
                            published_date, verified, keywords, affected_products,
                            updated_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                    """, (
                        exploit.id,
                        exploit.cve_id,
                        exploit.title,
                        exploit.description,
                        exploit.platform,
                        exploit.exploit_type,
                        exploit.payload,
                        exploit.source,
                        exploit.source_id,
                        exploit.reference_url,
                        exploit.author,
                        exploit.published_date,
                        1 if exploit.verified else 0,
                        json.dumps(exploit.keywords),
                        json.dumps(exploit.affected_products)
                    ))
                    success_count += 1
                except Exception as e:
                    logger.warning(f"Failed to insert exploit {exploit.id}: {e}")
            
            self.conn.commit()
        except Exception as e:
            logger.error(f"Bulk exploit insert failed: {e}")
            self.conn.rollback()
        
        return success_count
    
    def get_exploit(self, exploit_id: str) -> Optional[ExploitRecord]:
        """Get an exploit by ID."""
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM exploits WHERE id = ?", (exploit_id,))
        row = cursor.fetchone()
        
        if row:
            return self._row_to_exploit(row)
        return None
    
    def get_exploits_by_cve(self, cve_id: str) -> List[ExploitRecord]:
        """Get all exploits associated with a CVE."""
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM exploits WHERE cve_id = ?", (cve_id.upper(),))
        return [self._row_to_exploit(row) for row in cursor.fetchall()]
    
    def _row_to_exploit(self, row: sqlite3.Row) -> ExploitRecord:
        """Convert database row to ExploitRecord."""
        return ExploitRecord(
            id=row['id'],
            title=row['title'],
            description=row['description'] or "",
            platform=row['platform'] or "",
            exploit_type=row['exploit_type'] or "",
            payload=row['payload'],
            cve_id=row['cve_id'],
            source=row['source'] or 'local',
            source_id=row['source_id'],
            reference_url=row['reference_url'],
            author=row['author'],
            published_date=row['published_date'],
            verified=bool(row['verified']),
            keywords=json.loads(row['keywords'] or '[]'),
            affected_products=json.loads(row['affected_products'] or '[]')
        )
    
    # =========================================================================
    # Search Operations
    # =========================================================================
    
    def search(
        self,
        query: str = "",
        severity: Optional[str] = None,
        platform: Optional[str] = None,
        exploit_type: Optional[str] = None,
        has_exploit: Optional[bool] = None,
        min_cvss: Optional[float] = None,
        max_cvss: Optional[float] = None,
        date_from: Optional[str] = None,
        date_to: Optional[str] = None,
        limit: int = 50,
        offset: int = 0
    ) -> Dict[str, Any]:
        """
        Search CVEs and exploits with filters.
        
        Returns dict with 'cves', 'exploits', 'total_cves', 'total_exploits'.
        """
        cursor = self._get_cursor()
        results = {"cves": [], "exploits": [], "total_cves": 0, "total_exploits": 0}
        
        # Search CVEs
        cve_conditions = []
        cve_params = []
        
        if query:
            if self._is_postgres():
                cve_conditions.append("(id ILIKE %s OR description ILIKE %s)")
                cve_params.extend([f"%{query}%", f"%{query}%"])
            else:
                # Use FTS for text search
                cve_conditions.append("id IN (SELECT id FROM cves_fts WHERE cves_fts MATCH ?)")
                cve_params.append(f'"{query}"*')
        
        if severity:
            cve_conditions.append("severity = %s" if self._is_postgres() else "severity = ?")
            cve_params.append(severity.upper())
        
        if min_cvss is not None:
            cve_conditions.append("(cvss_v3_score >= %s OR cvss_v2_score >= %s)" if self._is_postgres() else "(cvss_v3_score >= ? OR cvss_v2_score >= ?)")
            cve_params.extend([min_cvss, min_cvss])
        
        if max_cvss is not None:
            cve_conditions.append("(cvss_v3_score <= %s OR cvss_v2_score <= %s)" if self._is_postgres() else "(cvss_v3_score <= ? OR cvss_v2_score <= ?)")
            cve_params.extend([max_cvss, max_cvss])
        
        if date_from:
            cve_conditions.append("published_date >= %s" if self._is_postgres() else "published_date >= ?")
            cve_params.append(date_from)
        
        if date_to:
            cve_conditions.append("published_date <= %s" if self._is_postgres() else "published_date <= ?")
            cve_params.append(date_to)
        
        if has_exploit is True:
            cve_conditions.append("id IN (SELECT DISTINCT cve_id FROM exploits WHERE cve_id IS NOT NULL)")
        
        cve_where = " AND ".join(cve_conditions) if cve_conditions else "1=1"
        
        # Get total count
        cursor.execute(f"SELECT COUNT(*) as cnt FROM cves WHERE {cve_where}", cve_params)
        results["total_cves"] = cursor.fetchone()['cnt']
        
        # Get paginated results
        limit_offset = "LIMIT %s OFFSET %s" if self._is_postgres() else "LIMIT ? OFFSET ?"
        cursor.execute(f"""
            SELECT * FROM cves 
            WHERE {cve_where} 
            ORDER BY COALESCE(cvss_v3_score, cvss_v2_score, 0) DESC, published_date DESC
            {limit_offset}
        """, cve_params + [limit, offset])
        
        results["cves"] = [self._row_to_cve(row) for row in cursor.fetchall()]
        
        # Search exploits
        exploit_conditions = []
        exploit_params = []
        
        if query:
            if self._is_postgres():
                exploit_conditions.append("(title ILIKE %s OR description ILIKE %s OR keywords ILIKE %s)")
                exploit_params.extend([f"%{query}%", f"%{query}%", f"%{query}%"])
            else:
                exploit_conditions.append(
                    "id IN (SELECT id FROM exploits_fts WHERE exploits_fts MATCH ?)"
                )
                exploit_params.append(f'"{query}"*')
        
        if platform:
            exploit_conditions.append("platform = %s" if self._is_postgres() else "platform = ?")
            exploit_params.append(platform.lower())
        
        if exploit_type:
            exploit_conditions.append("exploit_type = %s" if self._is_postgres() else "exploit_type = ?")
            exploit_params.append(exploit_type.lower())
        
        exploit_where = " AND ".join(exploit_conditions) if exploit_conditions else "1=1"
        
        cursor.execute(f"SELECT COUNT(*) as cnt FROM exploits WHERE {exploit_where}", exploit_params)
        results["total_exploits"] = cursor.fetchone()['cnt']
        
        cursor.execute(f"""
            SELECT * FROM exploits 
            WHERE {exploit_where}
            ORDER BY published_date DESC
            {limit_offset}
        """, exploit_params + [limit, offset])
        
        results["exploits"] = [self._row_to_exploit(row) for row in cursor.fetchall()]
        
        return results
    
    def search_by_product(self, vendor: str = "", product: str = "", version: str = "") -> List[CVERecord]:
        """Search CVEs affecting a specific product."""
        cursor = self.conn.cursor()
        
        conditions = []
        params = []
        
        if vendor:
            conditions.append("vendor LIKE ?")
            params.append(f"%{vendor.lower()}%")
        
        if product:
            conditions.append("product LIKE ?")
            params.append(f"%{product.lower()}%")
        
        if not conditions:
            return []
        
        where = " AND ".join(conditions)
        
        cursor.execute(f"""
            SELECT DISTINCT c.* FROM cves c
            JOIN cpe_matches m ON c.id = m.cve_id
            WHERE {where}
            ORDER BY COALESCE(c.cvss_v3_score, c.cvss_v2_score, 0) DESC
            LIMIT 100
        """, params)
        
        return [self._row_to_cve(row) for row in cursor.fetchall()]
    
    def match_exploits_by_keywords(self, keywords: List[str]) -> List[ExploitRecord]:
        """
        Find exploits that match given keywords.
        Useful for exploits without CVE IDs.
        """
        if not keywords:
            return []
        
        cursor = self.conn.cursor()
        
        # Build FTS query
        query_parts = [f'"{kw}"*' for kw in keywords[:10]]  # Limit to 10 keywords
        fts_query = " OR ".join(query_parts)
        
        cursor.execute("""
            SELECT e.* FROM exploits e
            WHERE e.id IN (
                SELECT id FROM exploits_fts WHERE exploits_fts MATCH ?
            )
            ORDER BY e.verified DESC
            LIMIT 50
        """, (fts_query,))
        
        return [self._row_to_exploit(row) for row in cursor.fetchall()]
    
    # =========================================================================
    # Metadata Operations
    # =========================================================================
    
    def get_metadata(self, key: str) -> Optional[str]:
        """Get a metadata value."""
        cursor = self.conn.cursor()
        cursor.execute("SELECT value FROM metadata WHERE key = ?", (key,))
        row = cursor.fetchone()
        return row['value'] if row else None
    
    def set_metadata(self, key: str, value: str):
        """Set a metadata value."""
        cursor = self.conn.cursor()
        cursor.execute(
            "INSERT OR REPLACE INTO metadata (key, value) VALUES (?, ?)",
            (key, value)
        )
        self.conn.commit()
    
    def get_last_sync(self, source: str = "nvd") -> Optional[datetime]:
        """Get the last sync timestamp for a source."""
        value = self.get_metadata(f"last_sync_{source}")
        if value:
            try:
                return datetime.fromisoformat(value)
            except ValueError:
                return None
        return None
    
    def set_last_sync(self, source: str = "nvd", timestamp: datetime = None):
        """Set the last sync timestamp for a source."""
        if timestamp is None:
            timestamp = datetime.utcnow()
        self.set_metadata(f"last_sync_{source}", timestamp.isoformat())
    
    # =========================================================================
    # Statistics
    # =========================================================================
    
    def get_stats(self) -> Dict[str, Any]:
        """Get database statistics."""
        cursor = self.conn.cursor()
        
        stats = {}
        
        # CVE counts
        cursor.execute("SELECT COUNT(*) as cnt FROM cves")
        stats["total_cves"] = cursor.fetchone()['cnt']
        
        cursor.execute("SELECT severity, COUNT(*) as cnt FROM cves GROUP BY severity")
        stats["cves_by_severity"] = {row['severity']: row['cnt'] for row in cursor.fetchall()}
        
        # Exploit counts
        cursor.execute("SELECT COUNT(*) as cnt FROM exploits")
        stats["total_exploits"] = cursor.fetchone()['cnt']
        
        cursor.execute("SELECT COUNT(*) as cnt FROM exploits WHERE cve_id IS NOT NULL")
        stats["exploits_with_cve"] = cursor.fetchone()['cnt']
        
        cursor.execute("SELECT COUNT(*) as cnt FROM exploits WHERE cve_id IS NULL")
        stats["exploits_without_cve"] = cursor.fetchone()['cnt']
        
        cursor.execute("SELECT platform, COUNT(*) as cnt FROM exploits GROUP BY platform")
        stats["exploits_by_platform"] = {row['platform']: row['cnt'] for row in cursor.fetchall()}
        
        cursor.execute("SELECT source, COUNT(*) as cnt FROM exploits GROUP BY source")
        stats["exploits_by_source"] = {row['source']: row['cnt'] for row in cursor.fetchall()}
        
        # Last sync times
        stats["last_sync_nvd"] = self.get_metadata("last_sync_nvd")
        stats["last_sync_exploitdb"] = self.get_metadata("last_sync_exploitdb")
        
        return stats
    
    def close(self):
        """Close database connection."""
        if self._conn:
            self._conn.close()
            self._conn = None


# Convenience function
def get_vuln_database() -> VulnDatabase:
    """Get the vulnerability database instance."""
    return VulnDatabase()


if __name__ == "__main__":
    # Test the database
    logging.basicConfig(level=logging.INFO)
    
    db = VulnDatabase(":memory:")
    
    # Test CVE insert
    cve = CVERecord(
        id="CVE-2021-44228",
        description="Log4j RCE vulnerability",
        cvss_v3_score=10.0,
        cvss_v3_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        published_date="2021-12-10"
    )
    db.upsert_cve(cve)
    
    # Test exploit insert (with CVE)
    exploit = ExploitRecord(
        id="log4shell_rce",
        title="Log4Shell RCE",
        description="Remote code execution via JNDI injection",
        platform="java",
        exploit_type="rce",
        cve_id="CVE-2021-44228",
        keywords=["log4j", "jndi", "ldap"]
    )
    db.upsert_exploit(exploit)
    
    # Test exploit insert (without CVE)
    exploit_no_cve = ExploitRecord(
        id="custom_sqli",
        title="Custom SQL Injection",
        description="Generic SQL injection payload",
        platform="generic",
        exploit_type="sqli",
        cve_id=None,  # No CVE
        keywords=["sql", "injection", "union"]
    )
    db.upsert_exploit(exploit_no_cve)
    
    # Test search
    results = db.search("log4j")
    print(f"Found {len(results['cves'])} CVEs and {len(results['exploits'])} exploits")
    
    # Test stats
    stats = db.get_stats()
    print(f"Stats: {json.dumps(stats, indent=2)}")
    
    print("Database test passed!")
