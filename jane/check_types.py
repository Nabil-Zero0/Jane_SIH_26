import sqlite3

conn = sqlite3.connect('data/jane.db')
c = conn.cursor()
types = c.execute('SELECT type, COUNT(*) FROM identifiers GROUP BY type').fetchall()
print('Identifier types breakdown:')
for t, cnt in types:
    print(f'  {t}: {cnt}')

commodities = c.execute("""
    SELECT COUNT(*) FROM identifiers 
    WHERE type IN ('COMMODITY','PRODUCT','WEAPON','NARCOTIC','DUMP','ESCROW')
""").fetchone()[0]
print(f'\nCommodities count matching _handle_commodities: {commodities}')

# Also check graph edges for SELLS or OFFERS
sells = c.execute("SELECT edge_type, COUNT(*) FROM graph_edges GROUP BY edge_type").fetchall()
print('\nGraph edges breakdown:')
for et, cnt in sells:
    print(f'  {et}: {cnt}')
