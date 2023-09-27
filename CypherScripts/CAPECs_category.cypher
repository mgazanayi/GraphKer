// ------------------------------------------------------------------------
// Insert Categories for CAPECs
UNWIND [capecCategoryFilesToImport] AS files

CALL apoc.periodic.iterate(
  'CALL apoc.load.json($files) YIELD value AS category RETURN category',
  '
    MERGE (capec:CAPEC {id: toInteger(category.ID)})
    SET capec.extendedName = category.Name,
    capec.status = category.Status,
    capec.summary = apoc.convert.toString(category.Summary),
    capec.notes = apoc.convert.toString(category.Notes),
    capec.submissionName = category.Content_History.Submission.Submission_Name,
    capec.submissionDate = datetime(category.Content_History.Submission.Submission_Date),
    capec.submissionOrganization = category.Content_History.Submission.Submission_Organization,
    capec.modification = [value IN category.Content_History.Modification | apoc.convert.toString(value)]

    // Insert Members for each Category
    WITH capec, category
    FOREACH (members IN category.Relationships.Has_Member |
      MERGE (capecMember:CAPEC {id: toInteger(members.CAPEC_ID)})
      MERGE (capec)-[:HAS_MEMBER]->(capecMember)
    )

    WITH capec, category
    FOREACH (categoryExReference IN category.References.Reference |
      MERGE (capecReference:CAPECReference {id: categoryExReference.External_Reference_ID})
      MERGE (capec)-[rel:HAS_EXTERNAL_REFERENCE]->(capecReference)
        SET rel.section = categoryExReference.Section
    )
  ',
  {batchSize:200, params: {files:files}}
) YIELD batches,total,timeTaken,committedOperations,failedOperations,failedBatches,retries,errorMessages,batch,operations,wasTerminated,failedParams,updateStatistics
    RETURN batches,total,timeTaken,committedOperations,failedOperations,failedBatches,retries,errorMessages,batch,operations,wasTerminated,failedParams,updateStatistics;