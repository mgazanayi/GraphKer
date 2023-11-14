CREATE CONSTRAINT cpe if NOT exists ON (cpe:CPE) ASSERT cpe.uri IS UNIQUE;

CREATE CONSTRAINT cve if NOT exists ON (cve:CVE) ASSERT cve.id IS UNIQUE;

CREATE CONSTRAINT cwe if NOT exists ON (cwe:CWE) ASSERT cwe.id IS UNIQUE;

CREATE CONSTRAINT reference if NOT exists ON (ref:CVEReference) ASSERT ref.url IS UNIQUE;

CREATE CONSTRAINT externalReferencecwe if NOT exists ON (ref:CWEReference) ASSERT ref.id IS UNIQUE;

CREATE CONSTRAINT Consequence if NOT exists ON (con:Consequence) ASSERT con.scope IS UNIQUE;

CREATE CONSTRAINT Mitigation if NOT exists ON (mit:Mitigation) ASSERT mit.description IS UNIQUE;

CREATE CONSTRAINT DetectionMethod if NOT exists ON (dec:DetectionMethod) ASSERT dec.method IS UNIQUE;

CREATE CONSTRAINT demonstrativeExample if NOT exists ON (de:DemonstrativeExample) ASSERT de.introText IS UNIQUE;

CREATE CONSTRAINT capec if NOT exists ON (cp:CAPEC) ASSERT cp.id IS UNIQUE;

CREATE CONSTRAINT cweview if NOT exists ON (v:CWEView) ASSERT v.id IS UNIQUE;

CREATE CONSTRAINT stakeholder if NOT exists ON (s:Stakeholder) ASSERT s.type IS UNIQUE;

CREATE INDEX AppPlatformType if NOT exists FOR (n:ApplicablePlatform) ON (n.type, n.prevalence, n.name, n.class);

CREATE CONSTRAINT externalReferencecapec if NOT exists ON (ref:CAPECReference) ASSERT ref.id IS UNIQUE;

CREATE CONSTRAINT capecview if NOT exists ON (v:CAPECView) ASSERT v.id IS UNIQUE;

