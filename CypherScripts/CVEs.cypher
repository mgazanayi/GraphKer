// Insert CVEs - Cypher Script
UNWIND [cveFilesToImport] AS files
CALL apoc.periodic.iterate(
        'CALL apoc.load.json($files) YIELD value AS item RETURN item',
        '
          MERGE (cve:CVE {
            id: item.cve.CVE_data_meta.ID
          })
            ON CREATE SET cve.assigner = item.cve.CVE_data_meta.ASSIGNER,
            cve.description = [desc IN item.cve.description.description_data WHERE desc.lang = "en" | desc.value],
            cve.publishedDate = datetime(item.publishedDate),
            cve.lastModifiedDate = datetime(item.lastModifiedDate)

        // In which CPE is applicable
          FOREACH (node IN item.configurations.nodes |
            FOREACH (cpe_value IN node.cpe_match |
              MERGE (cpe:CPE {
                uri: cpe_value.cpe23Uri
              })
              MERGE (cve)-[:IS_APPLICABLE_IN {isVulnerable: cpe_value.vulnerable}]->(cpe)
            )
          )

        // To which CWE belongs
          FOREACH (problemtype_data IN item.cve.problemtype.problemtype_data |
            FOREACH (CWE IN problemtype_data.description |
              MERGE (cwe:CWE { id: CWE.value })
                ON CREATE  SET cve.language = CWE.lang
              MERGE (cve)-[:BELONGS_TO_PROBLEM_TYPE]->(cwe)
            )
          )

        // CVSS3
          MERGE (cvss3:CVSS_3 {
            id: apoc.util.sha512([item.impact.baseMetricV3.cvssV3.version, item.impact.baseMetricV3.cvssV3.vectorString, item.impact.baseMetricV3.cvssV3.attackVector, item.impact.baseMetricV3.cvssV3.attackComplexity, item.impact.baseMetricV3.cvssV3.privilegesRequired, item.impact.baseMetricV3.cvssV3.userInteraction, item.impact.baseMetricV3.cvssV3.scope, item.impact.baseMetricV3.cvssV3.confidentialityImpact, item.impact.baseMetricV3.cvssV3.integrityImpact, item.impact.baseMetricV3.cvssV3.availabilityImpact, item.impact.baseMetricV3.cvssV3.baseScore, item.impact.baseMetricV3.cvssV3.baseSeverity, item.cve.impact.baseMetricV3.exploitabilityScore, item.cve.impact.baseMetricV3.impactScore])
          })
            ON CREATE  SET cvss3.version = item.impact.baseMetricV3.cvssV3.version,
            cvss3.vectorString = item.impact.baseMetricV3.cvssV3.vectorString,
            cvss3.attackVector = item.impact.baseMetricV3.cvssV3.attackVector,
            cvss3.attackComplexity = item.impact.baseMetricV3.cvssV3.attackComplexity,
            cvss3.privilegesRequired = item.impact.baseMetricV3.cvssV3.privilegesRequired,
            cvss3.userInteraction = item.impact.baseMetricV3.cvssV3.userInteraction,
            cvss3.cope = item.impact.baseMetricV3.cvssV3.scope,
            cvss3.confidentialityImpact = item.impact.baseMetricV3.cvssV3.confidentialityImpact,
            cvss3.integrityImpact = item.impact.baseMetricV3.cvssV3.integrityImpact,
            cvss3.availabilityImpact = item.impact.baseMetricV3.cvssV3.availabilityImpact,
            cvss3.baseScore = item.impact.baseMetricV3.cvssV3.baseScore,
            cvss3.baseSeverity = item.impact.baseMetricV3.cvssV3.baseSeverity,
            cvss3.exploitabilityScore = item.cve.impact.baseMetricV3.exploitabilityScore,
            cvss3.impactScore = item.cve.impact.baseMetricV3.impactScore
          MERGE (cve)-[:HAS_CVSS3_SCORE]->(cvss3)

          // CVSS2
          MERGE (cvss2:CVSS_2 {
            id: apoc.util.sha512([item.impact.baseMetricV2.cvssV2.version, item.impact.baseMetricV2.cvssV2.vectorString, item.impact.baseMetricV2.cvssV2.accessVector, item.impact.baseMetricV2.cvssV2.accessComplexity, item.impact.baseMetricV2.cvssV2.authentication, item.impact.baseMetricV2.cvssV2.confidentialityImpact, item.impact.baseMetricV2.cvssV2.integrityImpact, item.impact.baseMetricV2.cvssV2.availabilityImpact, item.impact.baseMetricV2.cvssV2.baseScore, item.cve.impact.baseMetricV2.exploitabilityScore, item.cve.impact.baseMetricV2.severity, item.cve.impact.baseMetricV2.impactScore, item.cve.impact.baseMetricV2.acInsufInfo, item.cve.impact.baseMetricV2.obtainAllPrivileges, item.cve.impact.baseMetricV2.obtainUserPrivileges, item.cve.impact.baseMetricV2.obtainOtherPrivileges, item.cve.impact.baseMetricV2.userInteractionRequired])
          })
            ON CREATE  SET cvss2.Version = item.impact.baseMetricV2.cvssV2.version,
            cvss2.vectorString = item.impact.baseMetricV2.cvssV2.vectorString,
            cvss2.accessVector = item.impact.baseMetricV2.cvssV2.accessVector,
            cvss2.accessComplexity = item.impact.baseMetricV2.cvssV2.accessComplexity,
            cvss2.authentication = item.impact.baseMetricV2.cvssV2.authentication,
            cvss2.confidentialityImpact = item.impact.baseMetricV2.cvssV2.confidentialityImpact,
            cvss2.integrityImpact = item.impact.baseMetricV2.cvssV2.integrityImpact,
            cvss2.availabilityImpact = item.impact.baseMetricV2.cvssV2.availabilityImpact,
            cvss2.baseScore = item.impact.baseMetricV2.cvssV2.baseScore,
            cvss2.exploitabilityScore = item.cve.impact.baseMetricV2.exploitabilityScore,
            cvss2.severity = item.cve.impact.baseMetricV2.severity,
            cvss2.impactScore = item.cve.impact.baseMetricV2.impactScore,
            cvss2.acInsufInfo = item.cve.impact.baseMetricV2.acInsufInfo,
            cvss2.obtainAllPrivileges = item.cve.impact.baseMetricV2.obtainAllPrivileges,
            cvss2.obtainUserPrivileges = item.cve.impact.baseMetricV2.obtainUserPrivileges,
            cvss2.obtainOtherPrivileges = item.cve.impact.baseMetricV2.obtainOtherPrivileges,
            cvss2.userInteractionRequired = item.cve.impact.baseMetricV2.userInteractionRequired
          MERGE (cve)-[:HAS_CVSS2_SCORE]->(cvss2)

        // Public References
          FOREACH (reference_data IN item.cve.references.reference_data |
            MERGE (cveReference:CVEReference {
              url: reference_data.url
            })
            ON CREATE SET cveReference.name = reference_data.name,
            cveReference.source = reference_data.refsource
            MERGE (cve)-[:REFERENCED_BY]->(cveReference)
          )
        ',
        {batchSize:200, params: {files: files}}
    ) YIELD batches,total,timeTaken,committedOperations,failedOperations,failedBatches,retries,errorMessages,batch,operations,wasTerminated,failedParams,updateStatistics
    RETURN batches,total,timeTaken,committedOperations,failedOperations,failedBatches,retries,errorMessages,batch,operations,wasTerminated,failedParams,updateStatistics;