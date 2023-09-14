import argparse
import webbrowser
from neo4j import GraphDatabase
import scraper
import time
import click
from Util import Util
from CPEInserter import CPEInserter
from CWEInserter import CWEInserter
from CVEInserter import CVEInserter
from CAPECInserter import CAPECInserter
from DatabaseUtil import DatabaseUtil

def download_datasets(import_path, cpe, cve, cwe, capec, all):
    try:
        start_time = time.time()

        import_path = Util.set_import_path(import_path)

        Util.clear_directories(import_path, cpe, cve, cwe, capec, all)

        scraper.download_datasets(import_path, cpe, cve, cwe, capec, all)

        Util.copy_files_cypher_script(import_path)

        end_time = time.time()

        execution_time = end_time - start_time
        print(f"Import finished in: {execution_time:.6f} seconds")

    except Exception as e:
        print(f"Error occurred while downloading files: {e}")

    return

def ingest_datasets(username, password, db_url, import_path, cpe, cve, cwe, capec, all, clean_database):
    try:
        start_time = time.time()

        import_path = Util.set_import_path(import_path)

        driver = GraphDatabase.driver(db_url, auth=(username, password))

        cpeInserter = CPEInserter(driver, import_path)
        cveInserter = CVEInserter(driver, import_path)
        cweInserter = CWEInserter(driver, import_path)
        capecInserter = CAPECInserter(driver, import_path)
        databaseUtil = DatabaseUtil(driver)

        if clean_database:
            databaseUtil.clear()
            databaseUtil.schema_script()

        if all:
            cpeInserter.cpe_insertion()
            capecInserter.capec_insertion()
            cveInserter.cve_insertion()
            cweInserter.cwe_insertion()
        else:
            if cpe:
                cpeInserter.cpe_insertion()
            if cve:
                cveInserter.cve_insertion()
            if cwe:
                cweInserter.cwe_insertion()
            if capec:
                capecInserter.capec_insertion()

        driver.close()

        end_time = time.time()

        execution_time = end_time - start_time
        print(f"Import finished in: {execution_time:.6f} seconds")

    except Exception as e:
        print(f"Error occurred: {e}")
        driver.close()
    return

@click.group
def cli():
    pass

@cli.command()
@click.option('--cpe', is_flag=True, help='Download CPE files')
@click.option('--cve', is_flag=True, help='Download CVE files')
@click.option('--cwe', is_flag=True, help='Download CWE files')
@click.option('--capec', is_flag=True, help='Download CAPEC files')
@click.option('--all', is_flag=True, help='Download CAPEC files')
@click.option('--import-path', required=True, help='Neo4j import path')
def download_files(import_path, cpe, cve, cwe, capec, all):
    if all and any([cpe, cve, cwe, capec]):
        click.echo("Please don't mix between all and specific files")
    elif (all and not any([cpe, cve, cwe, capec])) or any([cpe, cve, cwe, capec]):
        download_datasets(import_path, cpe, cve, cwe, capec, all)
    else:
        click.echo("Please choose an option all or at least one filetype from [cpe, cve, cwe, capec]")
    return

@cli.command()
@click.option('--username', required=True, help='Neo4j username')
@click.option('--password', required=True, help='Neo4j password')
@click.option('--db-url', required=True, help='Neo4j database url')
@click.option('--import-path', required=True, help='Neo4j import path')
@click.option('--cpe', is_flag=True, help='Download CPE files')
@click.option('--cve', is_flag=True, help='Download CVE files')
@click.option('--cwe', is_flag=True, help='Download CWE files')
@click.option('--capec', is_flag=True, help='Download CAPEC files')
@click.option('--all', is_flag=True, help='Download CAPEC files')
@click.option('--clean-database', is_flag=True, default=False, help='Remove entries from database (only cpe, cve, cwe and capec)')
def ingest_files(username, password, db_url, import_path, cpe, cve, cwe, capec, all, clean_database):
    if username and password and db_url and import_path:
        if all and any([cpe, cve, cwe, capec]):
            click.echo("Please don't mix between all and (cpe, cve, cwe, capec)")
        elif (all and not any([cpe, cve, cwe, capec])) or (any([cpe, cve, cwe, capec])):
            ingest_datasets(username, password, db_url, import_path, cpe, cve, cwe, capec, all, clean_database)
        else:
            click.echo("Please choose an option all or at least one filetype from [cpe, cve, cwe, capec]")
    else:
        click.echo("Options must not be empty")
    return

@cli.command()
@click.option('--cpe', is_flag=True, help='Download CPE files')
@click.option('--cve', is_flag=True, help='Download CVE files')
@click.option('--cwe', is_flag=True, help='Download CWE files')
@click.option('--capec', is_flag=True, help='Download CAPEC files')
@click.option('--all', is_flag=True, help='Download CAPEC files')
@click.option('--clean-database', is_flag=True, default=False, help='Remove entries from database (only cpe, cve, cwe and capec)')
@click.option('--username', required=True, help='Neo4j username')
@click.option('--password', required=True, help='Neo4j password')
@click.option('--db-url', required=True, help='Neo4j database url')
@click.option('--import-path', required=True, help='Neo4j import path')
def download_and_ingest(cpe, cve, cwe, capec, all, clean_database, username, password, db_url, import_path):
    if username and password and db_url and import_path:
        if all and any([cpe, cve, cwe, capec]):
            click.echo("Please don't mix between all and (cpe, cve, cwe, capec)")
        elif (all and not any([cpe, cve, cwe, capec])) or (any([cpe, cve, cwe, capec])):
            download_datasets(import_path, cpe, cve, cwe, capec, all)
            ingest_datasets(username, password, db_url, import_path, cpe, cve, cwe, capec, all, clean_database)
        else:
            click.echo("Please choose an option all or at least one filetype from [cpe, cve, cwe, capec]")
    else:
        click.echo("Options must not be empty")
    return

if __name__ == '__main__':
    try:
        cli()
    except click.exceptions.MissingParameter as e:
        # Handle missing parameters
        click.echo(f'Missing parameter: {e.param}')