import sqlite3
import json

hash_types_dict={}
source_libs_dict={}
symbol_hashes_dict={}

conn = sqlite3.connect('sc_hashes.db')
c = conn.cursor()

c.execute("SELECT * FROM hash_types")
hash_types = c.fetchall() 

for type in hash_types:
    hash_types_dict.update({type[0]:type[2]})

c.execute("SELECT * FROM source_libs")
source_libs = c.fetchall() 

for source_lib in source_libs:
    source_libs_dict.update({source_lib[0]:source_lib[1]})

c.execute("SELECT * FROM symbol_hashes")
symbol_hashes = c.fetchall()

for symbol_hashe in symbol_hashes:
    symbol_hashes_dict.update({symbol_hashe[1]:{"hash_type":symbol_hashe[2], "lib_key":symbol_hashe[3], "symbol_name":symbol_hashe[4]}})


sc_hashes = {
    "hash_types":hash_types_dict,
    "source_libs":source_libs_dict,
    "symbol_hashes":symbol_hashes_dict
    }

with open("sc_hashes.json", 'w') as f:
    json.dump(sc_hashes, f)
