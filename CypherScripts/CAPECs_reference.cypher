// Insert CAPECs Catalog - Cypher Script

UNWIND [capecReferenceFilesToImport] AS files

CALL apoc.periodic.iterate(
  'CALL apoc.load.json($files) YIELD value AS reference RETURN reference',
  '
    // Insert External References for CAPECs
    MERGE (capecReference:CAPECReference {id: reference.Reference_ID})
      SET capecReference.author = [value IN reference.Author | value],
      capecReference.title = reference.Title,
      capecReference.edition = reference.Edition,
      capecReference.url = reference.URL,
      capecReference.publicationYear = reference.Publication_Year,
      capecReference.publisher = reference.Publisher
  ',
  {batchSize:200, params: {files:files}}
) YIELD batches,total,timeTaken,committedOperations,failedOperations,failedBatches,retries,errorMessages,batch,operations,wasTerminated,failedParams,updateStatistics
    RETURN batches,total,timeTaken,committedOperations,failedOperations,failedBatches,retries,errorMessages,batch,operations,wasTerminated,failedParams,updateStatistics;