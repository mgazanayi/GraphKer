// ------------------------------------------------------------------------
// Insert Weaknesses for CWEs
UNWIND [cweWeaknessFilesToImport] AS files
CALL apoc.periodic.iterate(
  'CALL apoc.load.json($files) YIELD value AS weakness RETURN weakness',
  '
    // Insert CWEs
    MERGE (cwe:CWE { id: "CWE-" + weakness.ID })
    SET cwe.extendedName = weakness.Name,
      cwe.abstraction = weakness.Abstraction,
      cwe.structure = weakness.Structure,
      cwe.status = weakness.Status,
      cwe.description = weakness.Description,
      cwe.extendedDescription = CASE apoc.meta.type(weakness.Extended_Description)
        WHEN "STRING"  THEN apoc.convert.toString(weakness.Extended_Description)
        WHEN "MAP" THEN apoc.convert.toString(weakness.Extended_Description.`xhtml:p`)
        ELSE null
      END,
      cwe.likelihoodOfExploit = weakness.Likelihood_Of_Exploit,
      cwe.backgroundDetails = apoc.convert.toString(weakness.Background_Details.Background_Detail),
      cwe.modesOfIntroduction = [value IN weakness.Modes_Of_Introduction.Introduction | value.Phase],
      cwe.submissionDate = datetime(weakness.Content_History.Submission.Submission_Date),
      cwe.submissionName = weakness.Content_History.Submission.Submission_Name,
      cwe.submissionOrganization = weakness.Content_History.Submission.Submission_Organization,
      cwe.modifications = [value IN weakness.Content_History.Modification | apoc.convert.toString(value)],
      cwe.alternateTerms = apoc.convert.toString(weakness.Alternate_Terms),
      cwe.notes = [value IN weakness.Notes.Note | apoc.convert.toString(value)],
      cwe.affectedResources = [value IN weakness.Affected_Resources.Affected_Resource | value],
      cwe.functionalAreas = [value IN weakness.Functional_Areas.Functional_Area | value]

    // Insert Related Weaknesses CWE --> CWE
    WITH cwe, weakness
    FOREACH (Rel_Weakness IN weakness.Related_Weaknesses.Related_Weakness |
      MERGE (relatedCWE:CWE {id: "CWE-" + Rel_Weakness.CWE_ID})
      MERGE (cwe)-[r:IS_RELATED_TO {nature: Rel_Weakness.Nature}]->(relatedCWE)
        SET r.ordinal=Rel_Weakness.Ordinal
    )

    // Insert Applicable Platforms for CWEs
    WITH cwe, weakness
    FOREACH (lg IN weakness.Applicable_Platforms.Language |
      MERGE (ap:ApplicablePlatform {type: "Language", prevalence: lg.Prevalence,
                                    name: coalesce(lg.Name, " NOT SET "), class: coalesce(lg.Class, " NOT SET ")})
      MERGE (cwe)-[:APPLICABLE_PLATEFORM]->(ap)
    )

    WITH cwe, weakness
    FOREACH (tch IN weakness.Applicable_Platforms.Technology |
      MERGE (ap:Applicable_Platform {type: "Technology", prevalence: tch.Prevalence,
                                    name: coalesce(tch.Name, " NOT SET "), class: coalesce(tch.Class, " NOT SET ")})
      MERGE (cwe)-[:APPLICABLE_PLATEFORM]->(ap)
    )
    
    WITH cwe, weakness
    FOREACH (arc IN weakness.Applicable_Platforms.Architecture |
      MERGE (ap:ApplicablePlatform {type: "Architecture", prevalence: arc.Prevalence,
                                    name: coalesce(arc.Name, " NOT SET "), class: coalesce(arc.Class, " NOT SET ")})
      MERGE (cwe)-[:APPLICABLE_PLATEFORM]->(ap)
    )

    WITH cwe, weakness
    FOREACH (os IN weakness.Applicable_Platforms.Operating_System |
      MERGE (ap:ApplicablePlatform {type: "Operating System", prevalence: os.Prevalence,
                                    name: coalesce(os.Name, " NOT SET "), class: coalesce(os.Class, " NOT SET ")})
      MERGE (cwe)-[:APPLICABLE_PLATEFORM]->(ap)
    )

    // Insert Demonstrative Examples for CWEs
    WITH cwe, weakness
    FOREACH (example IN weakness.Demonstrative_Examples.Demonstrative_Example |
      MERGE (ex:DemonstrativeExample {
        introText: apoc.convert.toString(example.Intro_Text)
      })
      SET ex.bodyText = [value IN example.Body_Text | apoc.convert.toString(value)],
      ex.exampleCode = [value IN example.Example_Code | apoc.convert.toString(value)]
      MERGE (cwe)-[r:HAS_EXAMPLE]->(ex)
    )

    // Insert Consequences for CWEs
    WITH cwe, weakness
    FOREACH (consequence IN weakness.Common_Consequences.Consequence |
      MERGE (con:Consequence {Scope: [value IN consequence.Scope | value]})
      MERGE (cwe)-[rel:HAS_CONSEQUENCE]->(con)
      SET rel.impact = [value IN consequence.Impact | value],
      rel.note = consequence.Note,
      rel.likelihood = consequence.Likelihood
    )

    // Insert Detection Methods for CWEs
    WITH cwe, weakness
    FOREACH (dec IN weakness.Detection_Methods.Detection_Method |
      MERGE (d:DetectionMethod {
        method: dec.Method
      })
      MERGE (cwe)-[wd:CAN_BE_DETECTED]->(d)
      SET wd.description = CASE apoc.meta.type(dec.Description)
        WHEN "STRING"  THEN apoc.convert.toString(dec.Description)
        WHEN "MAP" THEN apoc.convert.toString(dec.Description.`xhtml:p`)
        ELSE null
      END
      SET wd.effectiveness = dec.Effectiveness,
      wd.effectivenessNotes = CASE apoc.meta.type(dec.Effectiveness_Notes)
        WHEN "STRING"  THEN apoc.convert.toString(dec.Effectiveness_Notes)
        WHEN "MAP" THEN apoc.convert.toString(dec.Effectiveness_Notes.`xhtml:p`)
        ELSE null
      END,
      wd.detectionMethodID = dec.Detection_Method_ID
    )

    // Insert Potential Mitigations for CWEs
    WITH cwe, weakness
    FOREACH (mit IN weakness.Potential_Mitigations.Mitigation |
      MERGE (m:Mitigation {description: apoc.convert.toString(mit.Description)})
      SET m.phase = [value IN mit.Phase | value],
        m.strategy = mit.Strategy,
        m.effectiveness = mit.Effectiveness,
        m.effectivenessNotes = CASE apoc.meta.type(mit.Effectiveness_Notes)
          WHEN "STRING"  THEN apoc.convert.toString(mit.Effectiveness_Notes)
          WHEN "MAP" THEN apoc.convert.toString(mit.Effectiveness_Notes.`xhtml:p`)
        ELSE null
      END,
      m.mitigationId = mit.Mitigation_ID
      MERGE (cwe)-[:HAS_MITIGATION]->(m)
    )

    // Insert Related Attack Patterns - CAPEC for CWEs
    WITH cwe, weakness
    FOREACH (rap IN weakness.Related_Attack_Patterns.Related_Attack_Pattern |
      MERGE (capec:CAPEC {
        id: toInteger(rap.CAPEC_ID)
      })
      MERGE (cwe)-[:IS_RELATED_TO]->(capec)
    )

    // Public References for CWEs
    WITH cwe, weakness
    FOREACH (exReference IN weakness.References.Reference |
      MERGE (ref:CWEReference {id: exReference.External_Reference_ID})
      MERGE (cwe)-[:HAS_EXTERNAL_REFERENCE]->(ref)
    )
  ',
  {batchSize:200, params: {files:files}}
) YIELD batches,total,timeTaken,committedOperations,failedOperations,failedBatches,retries,errorMessages,batch,operations,wasTerminated,failedParams,updateStatistics
    RETURN batches,total,timeTaken,committedOperations,failedOperations,failedBatches,retries,errorMessages,batch,operations,wasTerminated,failedParams,updateStatistics;