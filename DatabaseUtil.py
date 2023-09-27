import time
from neo4j import exceptions

class DatabaseUtil:

    def __init__(self, driver):
        self.driver = driver

    # Clear Database
    def clear(self):
        # Clear Database from existing nodes and relationships
        start_time = time.time()
        print(f"\Start cleaning Data from from existing nodes and relationships")
        labels = ["CPE", "CVE", "CVSS_2", "CVSS_3", "CVEReference", "CWE", "DetectionMethod", "DemonstrativeExample", "CWEReference", "CWEView", "Stakeholder", "ApplicablePlatform", "Mitigation", "Consequence", "CAPEC", "CAPECReference", "CAPECVIEW"]
        for label in labels:
            print(f"Deleting {label}")
            query = "CALL apoc.periodic.iterate('MATCH (n:" + label + ") RETURN n', 'DETACH DELETE n', {batchSize:2000})"
            try:
                with self.driver.session() as session:
                    session.run(query)
            except exceptions.Neo4jError as e:
                print(f"Neo4jError: {e}")
            print(f"{label} deleted successfuly")

        end_time = time.time()

        print(f"\nPrevious Data have been deleted within {end_time - start_time}")

        self.clear_schema()
        print("\nDatabase is clear and ready for imports.")

    # Clear Schema
    def clear_schema(self):
        # Clear Database from existing constraints and indexes
        print(f"\Start cleaning Data from existing constraints and indexes")
        start_time = time.time()
        query = """CALL apoc.cypher.runSchemaFile("ClearConstraintsIndexes.cypher")"""
        try:
            with self.driver.session() as session:
                session.run(query)
        except exceptions.Neo4jError as e:
            print(f"Neo4jError: {e}")
        end_time = time.time()
        print(f"\nPrevious Schema has been deleted {end_time - start_time}")

    # Constraints and Indexes
    def schema_script(self):
        # Create Constraints and Indexes
        print(f"\Start creating Constraints and Indexes")
        start_time = time.time()
        query = """CALL apoc.cypher.runSchemaFile("ConstraintsIndexes.cypher")"""
        try:
            with self.driver.session() as session:
                session.run(query)
        except exceptions.Neo4jError as e:
            print(f"Neo4jError: {e}")
        end_time = time.time()
        print(f"\nSchema with Constraints and Indexes insertion completed {end_time - start_time}")