// ------------------------------------------------------------------------
// Insert Views for CAPECs

UNWIND [capecViewFilesToImport] AS files
CALL apoc.periodic.iterate(
  'CALL apoc.load.json($files) YIELD value AS view RETURN view',
  '
    MERGE (capecView:CAPECVIEW {id: : toInteger(view.ID)})
      SET capecView.name = view.Name,
      capecView.type = view.Type,
      capecView.status = view.Status,
      capecView.objective = apoc.convert.toString(view.Objective),
      capecView.filter = view.Filter,
      capecView.notes = apoc.convert.toString(view.Notes),
      capecView.submissionName = view.Content_History.Submission.Submission_Name,
      capecView.submissionDate = datetime(view.Content_History.Submission.Submission_Date),
      capecView.submissionOrganization = view.Content_History.Submission.Submission_Organization,
      capecView.modification = [value IN view.Content_History.Modification | apoc.convert.toString(value)]

      // Insert Stakeholders for each View
      FOREACH (value IN view.Audience.Stakeholder |
        MERGE (stackholder:Stakeholder {type: value.Type})
          ON CREATE SET stackholder.description = value.Description
        MERGE (capecView)-[rel:USEFUL_FOR]->(stackholder)
      )

      // Insert Members for each View
      WITH capecView, view
      FOREACH (members IN view.Members.Has_Member |
        MERGE (MemberAP:CAPEC {id: toInteger(members.CAPEC_ID)})
        MERGE (capecView)-[:HAS_MEMBER]->(MemberAP)
      )


      // ------------------------------------------------------------------------
      // Insert Public References for each View
      WITH capecView, view
      FOREACH (viewExReference IN view.References.Reference |
        MERGE (viewRef:CAPECReference {id: viewExReference.External_Reference_ID})
        MERGE (capecView)-[:HAS_EXTERNAL_REFERENCE]->(viewRef)
      )
  ',
  {batchSize:200, params: {files:files}}
) YIELD batches,total,timeTaken,committedOperations,failedOperations,failedBatches,retries,errorMessages,batch,operations,wasTerminated,failedParams,updateStatistics
    RETURN batches,total,timeTaken,committedOperations,failedOperations,failedBatches,retries,errorMessages,batch,operations,wasTerminated,failedParams,updateStatistics;
