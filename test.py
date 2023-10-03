from neo4j import GraphDatabase
import click

@click.group
def cli():
    pass

@cli.command()
@click.option('--db-url', required=True, help='Neo4j database url')
@click.option('--username', required=True, help='Neo4j username')
@click.option('--password', required=True, help='Neo4j password')
@click.option('--database', default='neo4j', help='Neo4j database')
def test(db_url, username, password, database):
    driver = GraphDatabase.driver(db_url, auth=(username, password))
    cypher_query = 'MATCH (n)RETURN COUNT(n) AS count'

    with driver.session(database=database) as session:
        results = session.execute_read(
            lambda tx: tx.run(cypher_query).data())
        for record in results:
            print(record['count'])

    driver.close()

if __name__ == '__main__':
    try:
        test()
    except click.exceptions.MissingParameter as e:
        # Handle missing parameters
        click.echo(f'Missing parameter: {e.param}')