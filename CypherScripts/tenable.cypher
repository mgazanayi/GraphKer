LOAD CSV WITH HEADERS FROM 'file:///tenable_report/tenable.tsv' AS line FIELDTERMINATOR '\t'
WITH split(substring(replace(line.cve, '\'', ''), 1, size(replace(line.cve, '\'', ''))-2),',') AS cves, line.Hostname AS hostname
UNWIND cves AS id
MATCH (cve:CVE {id: id})
MERGE (server:Server {hostname: hostname})
MERGE (server)-[:IS_AFFECTED_BY]->(cve)
