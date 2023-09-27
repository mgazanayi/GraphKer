// ------------------------------------------------------------------------
// Insert Categories for CWEs
UNWIND [cweCategoryFilesToImport] AS files
CALL apoc.periodic.iterate(
  'CALL apoc.load.json($files) YIELD value AS category RETURN category',
  '
    MERGE (cwe:CWE { id: "CWE-" + category.ID })
      SET cwe.extendedName = category.Name,
      cwe.status = category.Status,
      cwe.summary = apoc.convert.toString(category.Summary),
      cwe.notes = apoc.convert.toString(category.Notes),
      cwe.submissionName = category.Content_History.Submission.Submission_Name,
      cwe.submissionDate = datetime(category.Content_History.Submission.Submission_Date),
      cwe.submissionOrganization = category.Content_History.Submission.Submission_Organization,
      cwe.modification = [value IN category.Content_History.Modification | apoc.convert.toString(value)]

    // Insert Members for each Category
    WITH cwe, category
    FOREACH (member IN category.Relationships.Has_Member |
      MERGE (cweMember:CWE {id: "CWE-" + member.CWE_ID})
      MERGE (cwe)-[:HAS_MEMBER {viewId: toInteger(member.View_ID)}]->(cweMember)
    )

    // ------------------------------------------------------------------------
    // Insert Public References for each Category
    WITH cwe, category
    FOREACH (categoryExReference IN category.References.Reference |
      MERGE (catRef:CWEReference {id: categoryExReference.External_Reference_ID})
      MERGE (cwe)-[:HAS_EXTERNAL_REFERENCE]->(catRef)
    )
  ',
  {batchSize:200, params: {files:files}}
) YIELD batches,total,timeTaken,committedOperations,failedOperations,failedBatches,retries,errorMessages,batch,operations,wasTerminated,failedParams,updateStatistics
    RETURN batches,total,timeTaken,committedOperations,failedOperations,failedBatches,retries,errorMessages,batch,operations,wasTerminated,failedParams,updateStatistics;