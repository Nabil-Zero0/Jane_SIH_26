import sqlite3
import os

con = sqlite3.connect("data/jane.db")
cur = con.cursor()

pages = cur.execute("SELECT id, url FROM pages").fetchall()
page_unimkts = None
for pid, purl in pages:
    if "unimkts" in purl:
        page_unimkts = pid
        break

ent_fav = cur.execute("SELECT id FROM entities WHERE entity_type='FAVICON_MMH3'").fetchone()
ent_srv = cur.execute("SELECT id FROM entities WHERE entity_type='SERVER_BANNER'").fetchone()
ent_wire = cur.execute("SELECT id FROM entities WHERE entity_type='WIRE_HANDLE'").fetchone()

if page_unimkts and ent_fav:
    cur.execute(
        "INSERT OR IGNORE INTO entity_relationships (id, entity_a_id, entity_b_id, relationship_type, source_page_id, confidence, first_seen) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (os.urandom(16).hex(), page_unimkts, ent_fav[0], "HAS_FAVICON", page_unimkts, 1.0, "2026-09-17 11:03:00")
    )
if page_unimkts and ent_srv:
    cur.execute(
        "INSERT OR IGNORE INTO entity_relationships (id, entity_a_id, entity_b_id, relationship_type, source_page_id, confidence, first_seen) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (os.urandom(16).hex(), page_unimkts, ent_srv[0], "RUNS_SERVER", page_unimkts, 1.0, "2026-09-17 11:03:00")
    )
if page_unimkts and ent_wire:
    cur.execute(
        "INSERT OR IGNORE INTO entity_relationships (id, entity_a_id, entity_b_id, relationship_type, source_page_id, confidence, first_seen) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (os.urandom(16).hex(), page_unimkts, ent_wire[0], "USES_HANDLE", page_unimkts, 0.9, "2026-09-17 10:53:32")
    )

con.commit()
print("Relationships:", cur.execute("SELECT relationship_type, count(*) FROM entity_relationships GROUP BY relationship_type").fetchall())
con.close()
