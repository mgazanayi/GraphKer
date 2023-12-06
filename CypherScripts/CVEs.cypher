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
            ON CREATE SET cvss3.version = item.impact.baseMetricV3.cvssV3.version,

            cvss3.vectorString = item.impact.baseMetricV3.cvssV3.vectorString,
            cvss3.attackVectorScore=
            CASE cvss3.attackVector
                WHEN "NETWORK" THEN 5
                WHEN "ADJACENT_NETWORK" THEN 4
                WHEN "LOCAL" THEN 2
                // "PHYSICAL"
                ELSE 1
            END,

            cvss3.attackVector = item.impact.baseMetricV3.cvssV3.attackVector,

            cvss3.attackComplexity = item.impact.baseMetricV3.cvssV3.attackComplexity,
            cvss3.attackComplexityScore=
            CASE item.impact.baseMetricV3.cvssV3.attackComplexity
                WHEN "LOW" THEN 5
                // "HIGH"
                ELSE 1
            END,

            cvss3.privilegesRequired = item.impact.baseMetricV3.cvssV3.privilegesRequired,
            cvss3.privilegesRequiredScore=
            CASE item.impact.baseMetricV3.cvssV3.privilegesRequired
                WHEN "NONE" THEN 5
                WHEN "LOW" THEN 3
                // "HIGH"
                ELSE 1
            END,

            cvss3.userInteraction = item.impact.baseMetricV3.cvssV3.userInteraction,
            cvss3.userInteractionScore=
            CASE item.impact.baseMetricV3.cvssV3.userInteraction
                WHEN "NONE" THEN 5
                // "REQUIRED"
                ELSE 0
            END,

            cvss3.scope = item.impact.baseMetricV3.cvssV3.scope,
            cvss3.scopeScore=
            CASE item.impact.baseMetricV3.cvssV3.scope
                WHEN "CHANGED" THEN 5
                // "UNCHANGED"
                ELSE 0
            END,

            cvss3.confidentialityImpact = item.impact.baseMetricV3.cvssV3.confidentialityImpact,
            cvss3.confidentialityImpactScore=
            CASE item.impact.baseMetricV3.cvssV3.confidentialityImpact
                WHEN "HIGH" THEN 5
                WHEN "LOW" THEN 3
                // "NONE"
                ELSE 0
            END,

            cvss3.integrityImpact = item.impact.baseMetricV3.cvssV3.integrityImpact,
            cvss3.integrityImpactScore=
            CASE item.impact.baseMetricV3.cvssV3.integrityImpact
                WHEN "HIGH" THEN 5
                WHEN "LOW" THEN 2
                // "NONE"
                ELSE 0
            END,

            cvss3.availabilityImpact = item.impact.baseMetricV3.cvssV3.availabilityImpact,
            cvss3.availabilityImpactScore=
            CASE item.impact.baseMetricV3.cvssV3.availabilityImpact
                WHEN "HIGH" THEN 5
                WHEN "LOW" THEN 3
                // "NONE"
                ELSE 0
            END,

            cvss3.baseScore = item.impact.baseMetricV3.cvssV3.baseScore,

            cvss3.baseSeverity = item.impact.baseMetricV3.cvssV3.baseSeverity,
            cvss3.baseSeverityScore=
            CASE item.impact.baseMetricV3.cvssV3.baseSeverity
                WHEN "CRITICAL" THEN 5
                WHEN "HIGH" THEN 4
                WHEN "MEDIUM" THEN 3
                // "LOW"
                ELSE 1
            END,

            cvss3.exploitabilityScore = item.cve.impact.baseMetricV3.exploitabilityScore,

            cvss3.impactScore = item.cve.impact.baseMetricV3.impactScore

          MERGE (attackComplexityCVSS3:CVSS3Topic {id: cvss3.id, topic: "attackComplexity"})
          MERGE (cvss3)-[:SCORED {current:cvss3.attackComplexityScore , target: 1}]->(attackComplexityCVSS3)

          MERGE (attackVectorCVSS3:CVSS3Topic {id: cvss3.id, topic: "attackVector"})
          MERGE (cvss3)-[:SCORED {current:cvss3.attackVectorScore, target: 1}]->(attackVectorCVSS3)

          MERGE (availabilityImpactCVSS3:CVSS3Topic {id: cvss3.id, topic: "availabilityImpact"})
          MERGE (cvss3)-[:SCORED {current:cvss3.availabilityImpactScore , target: 0}]->(availabilityImpactCVSS3)

          MERGE (baseSeverityCVSS3:CVSS3Topic {id: cvss3.id, topic: "baseSeverity"})
          MERGE (cvss3)-[:SCORED {current:cvss3.baseSeverityScore , target: 1}]->(baseSeverityCVSS3)

          MERGE (scopeCVSS3:CVSS3Topic {id: cvss3.id, topic: "scope"})
          MERGE (cvss3)-[:SCORED {current:cvss3.scopeScore , target: 0}]->(scopeCVSS3)

          MERGE (integrityImpactCVSS3:CVSS3Topic {id: cvss3.id, topic: "integrityImpact"})
          MERGE (cvss3)-[:SCORED {current:cvss3.integrityImpactScore , target: 0}]->(integrityImpactCVSS3)

          MERGE (privilegesRequiredCVSS3:CVSS3Topic {id: cvss3.id, topic: "privilegesRequired"})
          MERGE (cvss3)-[:SCORED {current:cvss3.privilegesRequiredScore , target: 0}]->(privilegesRequiredCVSS3)

          MERGE (userInteractionCVSS3:CVSS3Topic {id: cvss3.id, topic: "userInteraction"})
          MERGE (cvss3)-[:SCORED {current:cvss3.userInteractionScore , target: 0}]->(userInteractionCVSS3)

          MERGE (cve)-[:HAS_CVSS3_SCORE]->(cvss3)

          // CVSS2
          MERGE (cvss2:CVSS_2 {
            id: apoc.util.sha512([item.impact.baseMetricV2.cvssV2.version, item.impact.baseMetricV2.cvssV2.vectorString, item.impact.baseMetricV2.cvssV2.accessVector, item.impact.baseMetricV2.cvssV2.accessComplexity, item.impact.baseMetricV2.cvssV2.authentication, item.impact.baseMetricV2.cvssV2.confidentialityImpact, item.impact.baseMetricV2.cvssV2.integrityImpact, item.impact.baseMetricV2.cvssV2.availabilityImpact, item.impact.baseMetricV2.cvssV2.baseScore, item.cve.impact.baseMetricV2.exploitabilityScore, item.cve.impact.baseMetricV2.severity, item.cve.impact.baseMetricV2.impactScore, item.cve.impact.baseMetricV2.acInsufInfo, item.cve.impact.baseMetricV2.obtainAllPrivileges, item.cve.impact.baseMetricV2.obtainUserPrivileges, item.cve.impact.baseMetricV2.obtainOtherPrivileges, item.cve.impact.baseMetricV2.userInteractionRequired])
          })
            ON CREATE SET cvss2.Version = item.impact.baseMetricV2.cvssV2.version,
            cvss2.vectorString = item.impact.baseMetricV2.cvssV2.vectorString,

            cvss2.accessVector = item.impact.baseMetricV2.cvssV2.accessVector,
            cvss2.accessVectorScore=
            CASE item.impact.baseMetricV2.cvssV2.accessVector
                WHEN "NETWORK" THEN 5
                WHEN "ADJACENT_NETWORK" THEN 3
                // "LOCAL"
                ELSE 1
            END,

            cvss2.accessComplexity = item.impact.baseMetricV2.cvssV2.accessComplexity,
            cvss2.accessComplexityScore=
            CASE item.impact.baseMetricV2.cvssV2.accessComplexity
                WHEN "LOW" THEN 5
                WHEN "MEDIUM" THEN 3
                // "HIGH"
                ELSE 1
            END,

            cvss2.authentication = item.impact.baseMetricV2.cvssV2.authentication,
            cvss2.authenticationScore=
            CASE item.impact.baseMetricV2.cvssV2.authentication
                WHEN "NONE" THEN 5
                WHEN "SINGLE" THEN 3
                // "MULTIPLE"
                ELSE 1
            END,

            cvss2.confidentialityImpact = item.impact.baseMetricV2.cvssV2.confidentialityImpact,
            cvss2.confidentialityImpactScore=
            CASE item.impact.baseMetricV2.cvssV2.confidentialityImpact
                WHEN "COMPLETE" THEN 5
                WHEN "PARTIAL" THEN 3
                // "NONE"
                ELSE 0
            END,

            cvss2.integrityImpact = item.impact.baseMetricV2.cvssV2.integrityImpact,
            cvss2.integrityImpactScore=
            CASE item.impact.baseMetricV2.cvssV2.integrityImpact
                WHEN "COMPLETE" THEN 5
                WHEN "PARTIAL" THEN 3
                // "NONE"
                ELSE 0
            END,

            cvss2.availabilityImpact = item.impact.baseMetricV2.cvssV2.availabilityImpact,
            cvss2.availabilityImpactScore=
            CASE item.impact.baseMetricV2.cvssV2.availabilityImpact
                WHEN "COMPLETE" THEN 5
                WHEN "PARTIAL" THEN 3
                // "NONE"
                ELSE 0
            END,

            cvss2.baseScore = item.impact.baseMetricV2.cvssV2.baseScore,

            cvss2.exploitabilityScore = item.cve.impact.baseMetricV2.exploitabilityScore,
            cvss2.severity = item.cve.impact.baseMetricV2.severity,
            cvss2.impactScore = item.cve.impact.baseMetricV2.impactScore,
            cvss2.acInsufInfo = item.cve.impact.baseMetricV2.acInsufInfo,
            cvss2.obtainAllPrivileges = item.cve.impact.baseMetricV2.obtainAllPrivileges,
            cvss2.obtainUserPrivileges = item.cve.impact.baseMetricV2.obtainUserPrivileges,
            cvss2.obtainOtherPrivileges = item.cve.impact.baseMetricV2.obtainOtherPrivileges,
            cvss2.userInteractionRequired = item.cve.impact.baseMetricV2.userInteractionRequired

          MERGE (accessVectorCVSS2:CVSS2Topic {id: cvss2.id, topic: "accessVector"})
          MERGE (cvss2)-[:SCORED {current:cvss2.accessVectorScore , target: 1}]->(accessVectorCVSS2)

          MERGE (accessComplexityCVSS2:CVSS2Topic {id: cvss2.id, topic: "accessComplexity"})
          MERGE (cvss2)-[:SCORED {current:cvss2.accessComplexityScore , target: 1}]->(accessComplexityCVSS2)

          MERGE (authenticationCVSS2:CVSS2Topic {id: cvss2.id, topic: "authentication"})
          MERGE (cvss2)-[:SCORED {current:cvss2.authenticationScore , target: 1}]->(authenticationCVSS2)

          MERGE (confidentialityImpactCVSS2:CVSS2Topic {id: cvss2.id, topic: "confidentialityImpact"})
          MERGE (cvss2)-[:SCORED {current:cvss2.confidentialityImpactScore , target: 0}]->(confidentialityImpactCVSS2)

          MERGE (integrityImpactCVSS2:CVSS2Topic {id: cvss2.id, topic: "integrityImpact"})
          MERGE (cvss2)-[:SCORED {current:cvss2.integrityImpactScore , target: 0}]->(integrityImpactCVSS2)

          MERGE (availabilityImpactCVSS2:CVSS2Topic {id: cvss2.id, topic: "availabilityImpact"})
          MERGE (cvss2)-[:SCORED {current:cvss2.availabilityImpactScore , target: 0}]->(availabilityImpactCVSS2)

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

