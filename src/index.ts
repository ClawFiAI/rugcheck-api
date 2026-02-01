/**
 * Rugcheck API - Token security analysis
 * Real implementation using GoPlus Security API
 */

// GoPlus Security API - Free, no API key required
const GOPLUS_API = 'https://api.gopluslabs.io/api/v1';

// Chain ID mapping for GoPlus
const CHAIN_IDS: Record<string, string> = {
  ethereum: '1',
  bsc: '56',
  polygon: '137',
  arbitrum: '42161',
  optimism: '10',
  avalanche: '43114',
  fantom: '250',
  base: '8453',
  cronos: '25',
  gnosis: '100',
};

export interface TokenCheck {
  address: string;
  chain: string;
  isHoneypot: boolean;
  isRugPull: boolean;
  riskScore: number;
  riskLevel: 'safe' | 'low' | 'medium' | 'high' | 'critical';
  risks: Risk[];
  contract: ContractInfo;
  tokenInfo?: TokenInfo;
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
  creator?: string;
  mintable: boolean;
  pausable: boolean;
  blacklist: boolean;
  whitelist: boolean;
  proxy: boolean;
  selfDestruct: boolean;
  externalCall: boolean;
  buyTax?: number;
  sellTax?: number;
  cannotBuy: boolean;
  cannotSellAll: boolean;
  slippageModifiable: boolean;
  hiddenOwner: boolean;
  antiWhale: boolean;
  tradingCooldown: boolean;
}

export interface TokenInfo {
  name?: string;
  symbol?: string;
  totalSupply?: string;
  decimals?: number;
  holderCount?: number;
  lpHolderCount?: number;
  lpTotalSupply?: string;
  creatorPercent?: number;
  ownerPercent?: number;
  top10HolderPercent?: number;
}

export interface GoPlusResponse {
  code: number;
  message: string;
  result: Record<string, GoPlusTokenData>;
}

export interface GoPlusTokenData {
  token_name?: string;
  token_symbol?: string;
  total_supply?: string;
  holder_count?: string;
  lp_holder_count?: string;
  lp_total_supply?: string;
  is_honeypot?: string;
  honeypot_with_same_creator?: string;
  is_open_source?: string;
  is_proxy?: string;
  is_mintable?: string;
  can_take_back_ownership?: string;
  owner_change_balance?: string;
  hidden_owner?: string;
  selfdestruct?: string;
  external_call?: string;
  buy_tax?: string;
  sell_tax?: string;
  cannot_buy?: string;
  cannot_sell_all?: string;
  slippage_modifiable?: string;
  is_blacklisted?: string;
  is_whitelisted?: string;
  is_anti_whale?: string;
  trading_cooldown?: string;
  transfer_pausable?: string;
  owner_address?: string;
  creator_address?: string;
  creator_percent?: string;
  owner_percent?: string;
  holders?: { address: string; percent: string }[];
}

/**
 * Fetch token security data from GoPlus API
 */
export async function fetchGoPlusData(chain: string, address: string): Promise<GoPlusTokenData | null> {
  const chainId = CHAIN_IDS[chain.toLowerCase()];
  if (!chainId) {
    console.warn(`Unsupported chain: ${chain}`);
    return null;
  }

  try {
    const url = `${GOPLUS_API}/token_security/${chainId}?contract_addresses=${address}`;
    const response = await fetch(url);
    const data: GoPlusResponse = await response.json();

    if (data.code !== 1 || !data.result) {
      return null;
    }

    // GoPlus returns data keyed by lowercase address
    const tokenData = data.result[address.toLowerCase()];
    return tokenData || null;
  } catch (error) {
    console.error('GoPlus API error:', error);
    return null;
  }
}

/**
 * Parse GoPlus data into our ContractInfo format
 */
export function parseContractInfo(data: GoPlusTokenData): ContractInfo {
  return {
    verified: data.is_open_source === '1',
    renounced: !data.owner_address || data.owner_address === '0x0000000000000000000000000000000000000000',
    owner: data.owner_address,
    creator: data.creator_address,
    mintable: data.is_mintable === '1',
    pausable: data.transfer_pausable === '1',
    blacklist: data.is_blacklisted === '1',
    whitelist: data.is_whitelisted === '1',
    proxy: data.is_proxy === '1',
    selfDestruct: data.selfdestruct === '1',
    externalCall: data.external_call === '1',
    buyTax: data.buy_tax ? parseFloat(data.buy_tax) * 100 : undefined,
    sellTax: data.sell_tax ? parseFloat(data.sell_tax) * 100 : undefined,
    cannotBuy: data.cannot_buy === '1',
    cannotSellAll: data.cannot_sell_all === '1',
    slippageModifiable: data.slippage_modifiable === '1',
    hiddenOwner: data.hidden_owner === '1',
    antiWhale: data.is_anti_whale === '1',
    tradingCooldown: data.trading_cooldown === '1',
  };
}

/**
 * Parse GoPlus data into TokenInfo
 */
export function parseTokenInfo(data: GoPlusTokenData): TokenInfo {
  // Calculate top 10 holder percentage
  let top10Percent = 0;
  if (data.holders && Array.isArray(data.holders)) {
    const top10 = data.holders.slice(0, 10);
    top10Percent = top10.reduce((sum, h) => sum + parseFloat(h.percent || '0'), 0);
  }

  return {
    name: data.token_name,
    symbol: data.token_symbol,
    totalSupply: data.total_supply,
    holderCount: data.holder_count ? parseInt(data.holder_count) : undefined,
    lpHolderCount: data.lp_holder_count ? parseInt(data.lp_holder_count) : undefined,
    lpTotalSupply: data.lp_total_supply,
    creatorPercent: data.creator_percent ? parseFloat(data.creator_percent) * 100 : undefined,
    ownerPercent: data.owner_percent ? parseFloat(data.owner_percent) * 100 : undefined,
    top10HolderPercent: top10Percent * 100,
  };
}

/**
 * Analyze contract for rug pull indicators
 */
export function analyzeContract(contract: ContractInfo, tokenInfo?: TokenInfo): Risk[] {
  const risks: Risk[] = [];

  // Critical risks
  if (contract.cannotSellAll) {
    risks.push({
      type: 'cannot_sell',
      severity: 'critical',
      description: 'Token cannot be sold completely - likely honeypot',
    });
  }

  if (contract.cannotBuy) {
    risks.push({
      type: 'cannot_buy',
      severity: 'critical',
      description: 'Token cannot be bought - trading disabled',
    });
  }

  if (contract.selfDestruct) {
    risks.push({
      type: 'self_destruct',
      severity: 'critical',
      description: 'Contract has self-destruct function - funds can be drained',
    });
  }

  // High risks
  if (!contract.verified) {
    risks.push({
      type: 'unverified',
      severity: 'high',
      description: 'Contract source code is not verified',
    });
  }

  if (contract.mintable) {
    risks.push({
      type: 'mintable',
      severity: 'high',
      description: 'Token supply can be increased (mintable)',
    });
  }

  if (contract.hiddenOwner) {
    risks.push({
      type: 'hidden_owner',
      severity: 'high',
      description: 'Contract has hidden owner functions',
    });
  }

  if (contract.externalCall) {
    risks.push({
      type: 'external_call',
      severity: 'high',
      description: 'Contract makes external calls - potential exploit vector',
    });
  }

  if (contract.sellTax && contract.sellTax > 10) {
    risks.push({
      type: 'high_sell_tax',
      severity: contract.sellTax > 30 ? 'critical' : 'high',
      description: `High sell tax: ${contract.sellTax.toFixed(1)}%`,
    });
  }

  if (contract.buyTax && contract.buyTax > 10) {
    risks.push({
      type: 'high_buy_tax',
      severity: contract.buyTax > 30 ? 'critical' : 'high',
      description: `High buy tax: ${contract.buyTax.toFixed(1)}%`,
    });
  }

  // Medium risks
  if (!contract.renounced && contract.owner) {
    risks.push({
      type: 'ownership',
      severity: 'medium',
      description: 'Contract ownership has not been renounced',
    });
  }

  if (contract.pausable) {
    risks.push({
      type: 'pausable',
      severity: 'medium',
      description: 'Contract can be paused, blocking transfers',
    });
  }

  if (contract.blacklist) {
    risks.push({
      type: 'blacklist',
      severity: 'medium',
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

  if (contract.slippageModifiable) {
    risks.push({
      type: 'slippage_modifiable',
      severity: 'medium',
      description: 'Slippage/tax can be modified by owner',
    });
  }

  // Token info risks
  if (tokenInfo) {
    if (tokenInfo.creatorPercent && tokenInfo.creatorPercent > 10) {
      risks.push({
        type: 'creator_concentration',
        severity: tokenInfo.creatorPercent > 30 ? 'high' : 'medium',
        description: `Creator holds ${tokenInfo.creatorPercent.toFixed(1)}% of supply`,
      });
    }

    if (tokenInfo.top10HolderPercent && tokenInfo.top10HolderPercent > 50) {
      risks.push({
        type: 'holder_concentration',
        severity: tokenInfo.top10HolderPercent > 70 ? 'high' : 'medium',
        description: `Top 10 holders control ${tokenInfo.top10HolderPercent.toFixed(1)}% of supply`,
      });
    }

    if (tokenInfo.holderCount && tokenInfo.holderCount < 50) {
      risks.push({
        type: 'low_holders',
        severity: 'low',
        description: `Only ${tokenInfo.holderCount} holders - low distribution`,
      });
    }
  }

  // Low risks
  if (contract.antiWhale) {
    risks.push({
      type: 'anti_whale',
      severity: 'low',
      description: 'Anti-whale mechanism enabled (may limit large transactions)',
    });
  }

  if (contract.tradingCooldown) {
    risks.push({
      type: 'trading_cooldown',
      severity: 'low',
      description: 'Trading cooldown enabled between transactions',
    });
  }

  return risks;
}

/**
 * Calculate risk score from risks (0-100)
 */
export function calculateRiskScore(risks: Risk[]): number {
  const weights: Record<Risk['severity'], number> = {
    low: 5,
    medium: 15,
    high: 25,
    critical: 40,
  };

  const score = risks.reduce((sum, r) => sum + weights[r.severity], 0);
  return Math.min(100, score);
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
export function checkHoneypot(data: GoPlusTokenData | null, contract: ContractInfo): boolean {
  // Direct honeypot flag from GoPlus
  if (data?.is_honeypot === '1') return true;
  if (data?.honeypot_with_same_creator === '1') return true;
  
  // Indirect indicators
  if (contract.cannotSellAll) return true;
  if (contract.sellTax && contract.sellTax > 50) return true;
  
  return false;
}

/**
 * Full token security check - Main function
 */
export async function checkToken(address: string, chain: string): Promise<TokenCheck> {
  // Fetch real data from GoPlus
  const goPlusData = await fetchGoPlusData(chain, address);
  
  // Parse contract info
  const contract = goPlusData 
    ? parseContractInfo(goPlusData)
    : {
        verified: false,
        renounced: false,
        mintable: false,
        pausable: false,
        blacklist: false,
        whitelist: false,
        proxy: false,
        selfDestruct: false,
        externalCall: false,
        cannotBuy: false,
        cannotSellAll: false,
        slippageModifiable: false,
        hiddenOwner: false,
        antiWhale: false,
        tradingCooldown: false,
      };

  // Parse token info
  const tokenInfo = goPlusData ? parseTokenInfo(goPlusData) : undefined;

  // Analyze risks
  const risks = analyzeContract(contract, tokenInfo);
  const riskScore = calculateRiskScore(risks);
  const riskLevel = getRiskLevel(riskScore);
  const isHoneypot = checkHoneypot(goPlusData, contract);
  const isRugPull = riskScore >= 70 || isHoneypot;

  return {
    address,
    chain,
    isHoneypot,
    isRugPull,
    riskScore,
    riskLevel,
    risks,
    contract,
    tokenInfo,
    timestamp: Date.now(),
  };
}

/**
 * Batch check multiple tokens
 */
export async function checkTokens(tokens: { address: string; chain: string }[]): Promise<TokenCheck[]> {
  const results: TokenCheck[] = [];
  
  // Process in parallel with concurrency limit
  const batchSize = 5;
  for (let i = 0; i < tokens.length; i += batchSize) {
    const batch = tokens.slice(i, i + batchSize);
    const batchResults = await Promise.all(
      batch.map(({ address, chain }) => checkToken(address, chain))
    );
    results.push(...batchResults);
  }
  
  return results;
}

/**
 * Quick honeypot check
 */
export async function isHoneypot(address: string, chain: string): Promise<boolean> {
  const result = await checkToken(address, chain);
  return result.isHoneypot;
}

/**
 * Get supported chains
 */
export function getSupportedChains(): string[] {
  return Object.keys(CHAIN_IDS);
}
