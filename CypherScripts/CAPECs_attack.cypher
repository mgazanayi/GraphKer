// Insert CAPECs
UNWIND [capecAttackFilesToImport] AS files

CALL apoc.periodic.iterate(
  'CALL apoc.load.json($files) YIELD value AS value RETURN value',
  '
    // Insert Attack Patterns for CAPECs
    MERGE (capec:CAPEC {
      id: toInteger(value.ID)
    })
      SET capec.extendedName = value.Name,
      capec.abstraction = value.Abstraction,
      capec.status = value.Status,
      capec.description = apoc.convert.toString(value.Description),
      capec.likelihoodOfAttack = value.Likelihood_Of_Attack,
      capec.typicalSeverity = value.Typical_Severity,
      capec.alternateTerms = [value IN value.Alternate_Terms.Alternate_Term | value.Term],
      capec.prerequisites = [value IN value.Prerequisites.Prerequisite | apoc.convert.toString(value)],
      capec.skillsRequired = [value IN value.Skills_Required.Skill | value.Level],
      capec.skillsRequiredDescription = [value IN value.Skills_Required.Skill | coalesce(apoc.convert.toString(value.text), " NOT SET ")],
      capec.mitigations = [value IN value.Mitigations.Mitigation | apoc.convert.toString(value)],
      capec.examples = [value IN value.Example_Instances.Example | apoc.convert.toString(value)],
      capec.notes = [value IN value.Notes.Note | apoc.convert.toString(value)],
      capec.submissionDate = datetime(value.Content_History.Submission.Submission_Date),
      capec.submissionName = value.Content_History.Submission.Submission_Name,
      capec.submissionOrganization = value.Content_History.Submission.Submission_Organization,
      capec.modifications = [value IN value.Content_History.Modification | apoc.convert.toString(value)],
      capec.resourcesRequired = [value IN value.Resources_Required.Resource | apoc.convert.toString(value)],
      capec.indicators = [value IN value.Indicators.Indicator | apoc.convert.toString(value)]

    // Consequences
    FOREACH (consequence IN value.Consequences.Consequence |
      MERGE (con:Consequence {scope: [value IN consequence.Scope | value]})
      MERGE (capec)-[rel:HAS_CONSEQUENCE]->(con)
      ON CREATE SET rel.impact = [value IN consequence.Impact | value],
        rel.note = consequence.Note,
        rel.likelihood = consequence.Likelihood
    )

    // Mitigations
    FOREACH (mit IN value.Mitigations.Mitigation |
      MERGE (mitigation:Mitigation {
        description: apoc.convert.toString(mit)
      })
      MERGE (capec)-[:HAS_MITIGATION]->(mitigation)
    )

    // Related Attack Patterns
    WITH capec, value
    FOREACH (Rel_AP IN value.Related_Attack_Patterns.Related_Attack_Pattern |
      MERGE (relatedCapec:CAPEC { id: toInteger(Rel_AP.CAPEC_ID) })
      MERGE (capec)-[:IS_RELATED_TO {nature: Rel_AP.Nature}]->(relatedCapec)
    )

    // Public References for CAPECs
    WITH capec, value
    FOREACH (ExReference IN value.References.Reference |
      MERGE (capecReference:CAPECReference {id: ExReference.External_Reference_ID})
      MERGE (capec)-[rel:HAS_EXTERNAL_REFERENCE]->(capecReference)
        SET rel.section = ExReference.Section
    )
  ',
  {batchSize:1000, params: {files:files}}
) YIELD batches,total,timeTaken,committedOperations,failedOperations,failedBatches,retries,errorMessages,batch,operations,wasTerminated,failedParams,updateStatistics
    RETURN batches,total,timeTaken,committedOperations,failedOperations,failedBatches,retries,errorMessages,batch,operations,wasTerminated,failedParams,updateStatistics;