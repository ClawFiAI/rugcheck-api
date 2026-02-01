/**
 * Rugcheck API - Token security analysis
 */

export interface TokenCheck {
  address: string;
  chain: string;
  isHoneypot: boolean;
  isRugPull: boolean;
  riskScore: number;
  riskLevel: 'safe' | 'low' | 'medium' | 'high' | 'critical';
  risks: Risk[];
  contract: ContractInfo;
  timestamp: number;
}

export interface Risk {
  type: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  description: string;
}

export interface ContractInfo {
  verified: boolean;
  renounced: boolean;
  owner?: string;
  mintable: boolean;
  pausable: boolean;
  blacklist: boolean;
  proxy: boolean;
  buyTax?: number;
  sellTax?: number;
  maxBuy?: number;
  maxSell?: number;
}

/**
 * Check contract for rug pull indicators
 */
export function analyzeContract(contract: ContractInfo): Risk[] {
  const risks: Risk[] = [];

  if (!contract.verified) {
    risks.push({
      type: 'unverified',
      severity: 'medium',
      description: 'Contract source code is not verified',
    });
  }

  if (!contract.renounced && contract.owner) {
    risks.push({
      type: 'ownership',
      severity: 'medium',
      description: 'Contract ownership has not been renounced',
    });
  }

  if (contract.mintable) {
    risks.push({
      type: 'mintable',
      severity: 'high',
      description: 'Token supply can be increased (mintable)',
    });
  }

  if (contract.pausable) {
    risks.push({
      type: 'pausable',
      severity: 'high',
      description: 'Contract can be paused, blocking transfers',
    });
  }

  if (contract.blacklist) {
    risks.push({
      type: 'blacklist',
      severity: 'high',
      description: 'Contract has blacklist functionality',
    });
  }

  if (contract.proxy) {
    risks.push({
      type: 'proxy',
      severity: 'medium',
      description: 'Contract is upgradeable (proxy pattern)',
    });
  }

  if (contract.buyTax && contract.buyTax > 10) {
    risks.push({
      type: 'high_buy_tax',
      severity: contract.buyTax > 20 ? 'critical' : 'high',
      description: `High buy tax: ${contract.buyTax}%`,
    });
  }

  if (contract.sellTax && contract.sellTax > 10) {
    risks.push({
      type: 'high_sell_tax',
      severity: contract.sellTax > 20 ? 'critical' : 'high',
      description: `High sell tax: ${contract.sellTax}%`,
    });
  }

  return risks;
}

/**
 * Calculate risk score from risks
 */
export function calculateRiskScore(risks: Risk[]): number {
  const weights = { low: 5, medium: 15, high: 25, critical: 40 };
  return Math.min(100, risks.reduce((sum, r) => sum + weights[r.severity], 0));
}

/**
 * Get risk level from score
 */
export function getRiskLevel(score: number): TokenCheck['riskLevel'] {
  if (score < 15) return 'safe';
  if (score < 35) return 'low';
  if (score < 55) return 'medium';
  if (score < 75) return 'high';
  return 'critical';
}

/**
 * Check if token is likely a honeypot
 */
export function checkHoneypot(contract: ContractInfo): boolean {
  // High sell tax is honeypot indicator
  if (contract.sellTax && contract.sellTax > 50) return true;
  // Blacklist + pausable is suspicious
  if (contract.blacklist && contract.pausable) return true;
  return false;
}

/**
 * Full token security check
 */
export function checkToken(address: string, chain: string, contract: ContractInfo): TokenCheck {
  const risks = analyzeContract(contract);
  const riskScore = calculateRiskScore(risks);
  const riskLevel = getRiskLevel(riskScore);
  const isHoneypot = checkHoneypot(contract);
  const isRugPull = riskScore >= 70;

  return {
    address,
    chain,
    isHoneypot,
    isRugPull,
    riskScore,
    riskLevel,
    risks,
    contract,
    timestamp: Date.now(),
  };
}
