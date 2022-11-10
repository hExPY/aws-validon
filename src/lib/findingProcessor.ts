import { ValidatePolicyCommandOutput } from '@aws-sdk/client-accessanalyzer';
import config from 'config';

const exceptions = config.get('exceptions')

const filterFindingsByAmountOfFindings = (findings: readonly {readonly policyName: string, readonly response: ValidatePolicyCommandOutput}[]) =>
  findings.filter(finding => finding.response.findings.length > 0)

const filterFindingsByExceptions = (findings: readonly {readonly policyName: string, readonly response: ValidatePolicyCommandOutput}[]) =>
  findings.map((findingObject) =>
    findingObject.response.findings.filter(
      (finding) =>
        (exceptions[findingObject.policyName] && !exceptions[findingObject.policyName].includes(finding.issueCode))
    ))



const filter = (findings: readonly {readonly policyName: string, readonly response: ValidatePolicyCommandOutput}[]) => {
  const nonEmptyFindings = filterFindingsByAmountOfFindings(findings);
  return filterFindingsByExceptions(nonEmptyFindings);
}

export default filter;
