import sqlite3
import os

con = sqlite3.connect("data/jane.db")
cur = con.cursor()

# Find or create root ONION_URL entity for unimkts
root_onion = "http://unimktsvidgh7bzkgxclqvpioubz7cpn5ty4jftnmuxx6ish6xudebqd.onion"
ent_onion = cur.execute("SELECT id FROM entities WHERE value = ?", (root_onion,)).fetchone()
now = "2026-09-17 10:53:31.573422"

page_row = cur.execute("SELECT id FROM pages WHERE url LIKE '%unimkts%'").fetchone()
page_id = page_row[0] if page_row else None

if not ent_onion:
    ent_onion_id = os.urandom(16).hex()
    cur.execute("""
        INSERT INTO entities 
        (id, page_id, entity_type, value, canonical_value, confidence, context_snippet, extraction_method, first_seen, last_seen, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (ent_onion_id, page_id, "ONION_URL", root_onion, root_onion, 1.0, "Root Darknet Marketplace Domain", "crawler", now, now, now))
else:
    ent_onion_id = ent_onion[0]

ent_fav = cur.execute("SELECT id FROM entities WHERE entity_type='FAVICON_MMH3'").fetchone()
ent_srv = cur.execute("SELECT id FROM entities WHERE entity_type='SERVER_BANNER'").fetchone()
ent_wire = cur.execute("SELECT id FROM entities WHERE entity_type='WIRE_HANDLE'").fetchone()

# Delete old broken relationships
cur.execute("DELETE FROM entity_relationships WHERE relationship_type IN ('HAS_FAVICON', 'RUNS_SERVER', 'USES_HANDLE')")

if ent_fav:
    cur.execute(
        "INSERT INTO entity_relationships (id, entity_a_id, entity_b_id, relationship_type, confidence, first_seen) VALUES (?, ?, ?, ?, ?, ?)",
        (os.urandom(16).hex(), ent_onion_id, ent_fav[0], "HAS_FAVICON", 1.0, "2026-09-17 11:03:00")
    )
if ent_srv:
    cur.execute(
        "INSERT INTO entity_relationships (id, entity_a_id, entity_b_id, relationship_type, confidence, first_seen) VALUES (?, ?, ?, ?, ?, ?)",
        (os.urandom(16).hex(), ent_onion_id, ent_srv[0], "RUNS_SERVER", 1.0, "2026-09-17 11:03:00")
    )
if ent_wire:
    cur.execute(
        "INSERT INTO entity_relationships (id, entity_a_id, entity_b_id, relationship_type, confidence, first_seen) VALUES (?, ?, ?, ?, ?, ?)",
        (os.urandom(16).hex(), ent_onion_id, ent_wire[0], "USES_HANDLE", 0.9, "2026-09-17 10:53:32")
    )

con.commit()
print("Fixed relationships:")
for r in cur.execute("""
    SELECT ea.entity_type, ea.value, r.relationship_type, eb.entity_type, eb.value 
    FROM entity_relationships r 
    JOIN entities ea ON r.entity_a_id=ea.id 
    JOIN entities eb ON r.entity_b_id=eb.id
""").fetchall():
    print(" ", r)
con.close()
