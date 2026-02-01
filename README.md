# Rugcheck API

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Real-time token security analysis API using [GoPlus Security](https://gopluslabs.io/) data. Detect honeypots, rug pulls, and contract risks.

## Features

- 🍯 **Honeypot Detection** - Identify tokens that can't be sold
- ⚠️ **Rug Pull Risk** - Assess contract vulnerabilities
- 📊 **Risk Scoring** - 0-100 risk score with severity levels
- 🔍 **Contract Analysis** - Detailed security checks
- 🌐 **Multi-chain** - 10+ EVM chains supported
- ⚡ **Fast API** - Built with Fastify

## Supported Chains

- Ethereum
- BSC (BNB Chain)
- Polygon
- Arbitrum
- Optimism
- Avalanche
- Fantom
- Base
- Cronos
- Gnosis

## Quick Start

```bash
# Install
npm install

# Development
npm run dev

# Production
npm run build && npm start
```

## API Endpoints

### Check Token
```
GET /check/:chain/:address
```

**Example:**
```bash
curl http://localhost:3001/check/ethereum/0x6982508145454Ce325dDbE47a25d4ec3d2311933
```

**Response:**
```json
{
  "address": "0x...",
  "chain": "ethereum",
  "isHoneypot": false,
  "isRugPull": false,
  "riskScore": 25,
  "riskLevel": "low",
  "risks": [
    {
      "type": "ownership",
      "severity": "medium",
      "description": "Contract ownership has not been renounced"
    }
  ],
  "contract": {
    "verified": true,
    "renounced": false,
    "mintable": false,
    "pausable": false,
    "buyTax": 0,
    "sellTax": 0,
    ...
  },
  "tokenInfo": {
    "name": "Pepe",
    "symbol": "PEPE",
    "holderCount": 250000,
    ...
  }
}
```

### Quick Honeypot Check
```
GET /honeypot/:chain/:address
```

### Risk Score Only
```
GET /risk/:chain/:address
```

### Batch Check
```
POST /check/batch
```

**Body:**
```json
{
  "tokens": [
    { "chain": "ethereum", "address": "0x..." },
    { "chain": "bsc", "address": "0x..." }
  ]
}
```

### Supported Chains
```
GET /chains
```

### Health Check
```
GET /health
```

## Risk Levels

| Score | Level | Description |
|-------|-------|-------------|
| 0-14 | Safe | Low risk, basic checks pass |
| 15-34 | Low | Minor concerns detected |
| 35-54 | Medium | Several risk factors |
| 55-74 | High | Significant risks |
| 75-100 | Critical | Extreme risk, likely scam |

## Risk Types Detected

**Critical:**
- Cannot sell (honeypot)
- Self-destruct function
- Cannot buy (trading disabled)

**High:**
- Unverified contract
- Mintable token
- Hidden owner
- External calls
- High tax (>10%)

**Medium:**
- Ownership not renounced
- Pausable transfers
- Blacklist functionality
- Proxy/upgradeable
- High holder concentration

**Low:**
- Anti-whale limits
- Trading cooldown
- Low holder count

## Docker

```bash
docker build -t rugcheck-api .
docker run -p 3001:3001 rugcheck-api
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| PORT | 3001 | Server port |
| HOST | 0.0.0.0 | Server host |

## Programmatic Usage

```typescript
import { checkToken, isHoneypot, checkTokens } from 'rugcheck-api';

// Full check
const result = await checkToken('0x...', 'ethereum');
console.log('Risk Score:', result.riskScore);
console.log('Is Honeypot:', result.isHoneypot);

// Quick honeypot check
const honeypot = await isHoneypot('0x...', 'bsc');

// Batch check
const results = await checkTokens([
  { address: '0x...', chain: 'ethereum' },
  { address: '0x...', chain: 'bsc' },
]);
```

## Data Source

This API uses the [GoPlus Security API](https://docs.gopluslabs.io/) which provides real-time token security data. No API key required.

## License

MIT © [ClawFi](https://github.com/ClawFiAI)

## Related

- [@clawfi/sdk](https://github.com/ClawFiAI/clawfi-sdk) - ClawFi SDK
- [token-scanner](https://github.com/ClawFiAI/token-scanner) - CLI tool
