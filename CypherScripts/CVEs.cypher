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
          CREATE (cvss3:CVSS_3)
            SET cvss3.version = item.impact.baseMetricV3.cvssV3.version,

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

          CREATE (attackComplexityCVSS3:CVSS3Topic {topic: "attackComplexity"})
          CREATE (cvss3)-[:SCORED {current:cvss3.attackComplexityScore , target: 1}]->(attackComplexityCVSS3)

          CREATE (attackVectorCVSS3:CVSS3Topic {topic: "attackVector"})
          CREATE (cvss3)-[:SCORED {current:cvss3.attackVectorScore, target: 1}]->(attackVectorCVSS3)

          CREATE (availabilityImpactCVSS3:CVSS3Topic {topic: "availabilityImpact"})
          CREATE (cvss3)-[:SCORED {current:cvss3.availabilityImpactScore , target: 0}]->(availabilityImpactCVSS3)

          CREATE (baseSeverityCVSS3:CVSS3Topic {topic: "baseSeverity"})
          CREATE (cvss3)-[:SCORED {current:cvss3.baseSeverityScore , target: 1}]->(baseSeverityCVSS3)

          CREATE (scopeCVSS3:CVSS3Topic {topic: "scope"})
          CREATE (cvss3)-[:SCORED {current:cvss3.scopeScore , target: 0}]->(scopeCVSS3)

          CREATE (integrityImpactCVSS3:CVSS3Topic {topic: "integrityImpact"})
          CREATE (cvss3)-[:SCORED {current:cvss3.integrityImpactScore , target: 0}]->(integrityImpactCVSS3)

          CREATE (privilegesRequiredCVSS3:CVSS3Topic {topic: "privilegesRequired"})
          CREATE (cvss3)-[:SCORED {current:cvss3.privilegesRequiredScore , target: 0}]->(privilegesRequiredCVSS3)

          CREATE (userInteractionCVSS3:CVSS3Topic {topic: "userInteraction"})
          CREATE (cvss3)-[:SCORED {current:cvss3.userInteractionScore , target: 0}]->(userInteractionCVSS3)

          CREATE (cve)-[:HAS_CVSS3_SCORE]->(cvss3)

          // CVSS2
          CREATE (cvss2:CVSS_2)
            SET cvss2.Version = item.impact.baseMetricV2.cvssV2.version,
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

          CREATE (accessVectorCVSS2:CVSS2Topic {topic: "accessVector"})
          CREATE (cvss2)-[:SCORED {current:cvss2.accessVectorScore , target: 1}]->(accessVectorCVSS2)

          CREATE (accessComplexityCVSS2:CVSS2Topic {topic: "accessComplexity"})
          CREATE (cvss2)-[:SCORED {current:cvss2.accessComplexityScore , target: 1}]->(accessComplexityCVSS2)

          CREATE (authenticationCVSS2:CVSS2Topic {topic: "authentication"})
          CREATE (cvss2)-[:SCORED {current:cvss2.authenticationScore , target: 1}]->(authenticationCVSS2)

          CREATE (confidentialityImpactCVSS2:CVSS2Topic {topic: "confidentialityImpact"})
          CREATE (cvss2)-[:SCORED {current:cvss2.confidentialityImpactScore , target: 0}]->(confidentialityImpactCVSS2)

          CREATE (integrityImpactCVSS2:CVSS2Topic {topic: "integrityImpact"})
          CREATE (cvss2)-[:SCORED {current:cvss2.integrityImpactScore , target: 0}]->(integrityImpactCVSS2)

          CREATE (availabilityImpactCVSS2:CVSS2Topic {topic: "availabilityImpact"})
          CREATE (cvss2)-[:SCORED {current:cvss2.availabilityImpactScore , target: 0}]->(availabilityImpactCVSS2)

          CREATE (cve)-[:HAS_CVSS2_SCORE]->(cvss2)

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

