import os
import time
import fnmatch
from neo4j import exceptions
import pandas as pd
import re
import json

class TenableInserter:

    def __init__(self, driver, import_path, database):
        self.driver = driver
        self.import_path = import_path
        self.database = database

    # Configure Tenable Files and for insertion
    def cve_plugin_output_insertion(self):
        print("\nInserting Tenable reports to Database...")
        files = self.files_to_insert_cve()
        for f in files:
            print('Inserting ' + f)
            self.insert_plugin_output_file(f)

    def insert_plugin_output_file(self, file):
        start_time = time.time()
        try:
            with self.driver.session(database=self.database) as session:
                with open(self.import_path + file, "r") as plugin_output_file:
                    csv_reader = pd.read_csv(plugin_output_file, chunksize=100, delimiter='\t')
                    for chunk in csv_reader:
                        # Process each chunk (chunk is a DataFrame)
                        for index, row in chunk.iterrows():
                            if ('Remote package installed :' in row['plugin_output']):
                                # Process each row
                                lines = row['plugin_output'].split('\n')
                                remote_package_lines = [line.split(':', 1)[1].strip() for line in lines if line.startswith('Remote package installed :')]
                                package_versions = []
                                for remote_package in remote_package_lines:
                                    package_versions.append(self.transform_package(remote_package))

                                #print(remote_package + '==>' + transformed_package)
                                query = f"""
                                        MATCH (pv:PackageVersion) WHERE pv.version_id IN { json.dumps(package_versions) }
                                        MATCH (cve:CVE) WHERE cve.id IN { row['cve'] }
                                        MERGE (pv)-[:IS_AFFECTED_BY]->(cve)
                                    """
                                session.run(query)

        except exceptions.Neo4jError as e:
            print(f"Neo4jError: {e}")
        except exceptions.DriverError as e:
            print(f"DriverError: {e}")
        except Exception as e:
            # Handle other exceptions
            print(f"An error occurred: {e}")

        end_time = time.time()

        print(f"\Tenable Files: { file } insertion completed within { end_time - start_time }\n----------")

    # Define which Dataset and Cypher files will be imported on CVE Insertion
    def files_to_insert_cve(self):
        listOfFiles = os.listdir(self.import_path + "tenable/")
        pattern = "*.tsv"
        tenable_files = []
        for entry in listOfFiles:
            if fnmatch.fnmatch(entry, pattern):
                if entry.startswith("CVE_plugin_output"):
                    tenable_files.append("tenable/" + entry)
                else:
                    continue

        return tenable_files
    
    def transform_package(self, package_name):
        # Define a regular expression pattern to capture the components
        pattern = re.compile(r'^([a-zA-Z0-9-\+]+)(?:-(.+))?$')
        # Use the pattern to match and capture components
        match = pattern.match(package_name)

        # If there's a match, format the result; otherwise, return the original string
        if match:
            name, version = match.groups()
            transformed_package = f"{name}#{version}"
            return transformed_package
        else:
            return package_name
