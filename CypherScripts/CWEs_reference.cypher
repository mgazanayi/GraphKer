// Insert CWEs Catalog - Cypher Script

UNWIND [cweReferenceFilesToImport] AS files
CALL apoc.periodic.iterate(
  'CALL apoc.load.json($files) YIELD value AS reference RETURN reference',
  '
    // Insert External References for CWEs
    MERGE (cweReference:CWEReference {id: reference.Reference_ID})
      ON CREATE SET cweReference.author = [value IN reference.Author | value],
      cweReference.title = reference.Title,
      cweReference.edition = reference.Edition,
      cweReference.url = reference.URL,
      cweReference.publicationYear = reference.Publication_Year,
      cweReference.publisher = reference.Publisher
  ',
  {batchSize:200, params: {files:files}}
) YIELD batches,total,timeTaken,committedOperations,failedOperations,failedBatches,retries,errorMessages,batch,operations,wasTerminated,failedParams,updateStatistics
    RETURN batches,total,timeTaken,committedOperations,failedOperations,failedBatches,retries,errorMessages,batch,operations,wasTerminated,failedParams,updateStatistics;