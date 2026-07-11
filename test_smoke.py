from pynetviz.collector.connection_collector import ConnectionCollector

c = ConnectionCollector()
records, stats, processes = c._collect()
print(f"connections={len(records)} total={stats.total_connections} processes={len(processes)}")