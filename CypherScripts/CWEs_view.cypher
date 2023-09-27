// ------------------------------------------------------------------------
// Insert Views for CWEs
UNWIND [cweViewFilesToImport] AS files
CALL apoc.periodic.iterate(
  'CALL apoc.load.json($files) YIELD value AS view RETURN view',
  '
    MERGE (cweView:CWEView {id: toInteger(view.ID)})
      SET cweView.name = view.Name,
      cweView.type = view.Type,
      cweView.status = view.Status,
      cweView.objective = apoc.convert.toString(view.Objective),
      cweView.filter = view.Filter,
      cweView.notes = apoc.convert.toString(view.Notes),
      cweView.submissionName = view.Content_History.Submission.Submission_Name,
      cweView.submissionDate = datetime(view.Content_History.Submission.Submission_Date),
      cweView.submissionOrganization = view.Content_History.Submission.Submission_Organization,
      cweView.modification = [value IN view.Content_History.Modification | apoc.convert.toString(value)]

    // Insert Stakeholders for each View
    FOREACH (value IN view.Audience.Stakeholder |
      MERGE (stakeholder:Stakeholder {type: value.Type})
      MERGE (cweView)-[rel:USEFUL_FOR]->(stakeholder)
      SET rel.Description = value.Description
    )

    // Insert Members for each View
    WITH cweView, view
    FOREACH (member IN view.Members.Has_Member |
      MERGE (cweMember:CWE {id: "CWE-" + member.CWE_ID})
      MERGE (cweView)-[:HAS_MEMBER]->(cweMember)
    )

    // ------------------------------------------------------------------------
    // Insert Public References for each View
    WITH cweView, view
    FOREACH (viewExReference IN view.References.Reference |
      MERGE (viewRef:CWEReference {id: viewExReference.External_Reference_ID})
      MERGE (cweView)-[:HAS_EXTERNAL_REFERENCE]->(viewRef)
    )
  ',
  {batchSize:200, params: {files:files}}
) YIELD batches,total,timeTaken,committedOperations,failedOperations,failedBatches,retries,errorMessages,batch,operations,wasTerminated,failedParams,updateStatistics
    RETURN batches,total,timeTaken,committedOperations,failedOperations,failedBatches,retries,errorMessages,batch,operations,wasTerminated,failedParams,updateStatistics;