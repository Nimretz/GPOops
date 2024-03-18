#from neo4j import GraphDatabase
import json
import sys
from py2neo import Graph, Node, NodeMatcher, Relationship, RelationshipMatcher

if len(sys.argv) < 2:
    print("Usage: Loadiel.py <path_to_json_file>")
    sys.exit(1)

json_file_path = sys.argv[1]
# driver = GraphDatabase.driver("bolt://localhost:7687", auth=("neo4j", "neo4j"))
# sess = driver.session()

# spooler_gpos = ['A52A4902-CA98-4371-8301-762B01AE24DC']
# query = '''UNWIND $gpos as gpo
# MATCH (g:GPO)
# WHERE g.objectid = gpo
# SET g.spooler = TRUE'''
# result = sess.run(query, parameters={'gpos':spooler_gpos}).data()
# print(result)

def safe_format_property_name(name):
    # Implement any necessary checks or formatting
    # For example, replace spaces with underscores, remove special characters, etc.
    # This is a basic placeholder implementation:
    return ''.join(c for c in name if c.isalnum() or c == '_')


with open(json_file_path, 'r') as file:
    services_data = json.load(file)

# Neo4j Connection
print("[+] Starting update neo4j aka your bloodhound...")
try:
    graph=Graph("bolt://localhost:7687", auth=("neo4j", "mefager922"))
    print("[+] Connect to Neo4j server: bolt://localhost:7687  (neo4j)")
    matcher=NodeMatcher(graph)
except Exception as e:
    print(str(e))
    exit()

for gpo in services_data:
    node = matcher.match("GPO").where(f'_.distinguishedname =~ ".*{gpo}.*"').first()
    if node:
        for service in services_data[gpo]:
            node[service["ServiceName"]] = service["ServiceStatus"]
        graph.push(node)
        
#driver = GraphDatabase.driver("bolt://localhost:7687", auth=("neo4j", "mefager922"))
#sess = driver.session()
"""
for gpo_id, services in services_data.items():
    gpo_id = str(gpo_id)
    for service in services:
        service_name = safe_format_property_name(service["ServiceName"])
        service_status = service["ServiceStatus"]
        try:
            query = f'''MATCH (g:GPO) WHERE g.objectid = $gpo_id SET g.{service_name} = $service_status RETURN g'''
            print(query)
            # Execute the query with parameters to avoid injection risks
            # print(query)
            result = sess.run(query, parameters={'gpo_id': gpo_id, 'service_status': service_status}).data()
            print(result)
        except Exception as e:
            print(f"Error updating GPO {gpo_id} for service {service_name}: {e}")

sess.close()
driver.close()

"""