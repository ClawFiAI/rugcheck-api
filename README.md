# Rugcheck API

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

API service for detecting rug pulls and honeypots in crypto tokens.

## Features

- 🔍 Contract analysis
- 🍯 Honeypot detection
- ⚠️ Risk scoring
- 🔐 Security checks
- ⚡ Fast API responses

## Installation

```bash
npm install
npm run build
npm start
```

## API Endpoints

### Health Check
```
GET /health
```

### Check Token
```
GET /check/:chain/:address
```

Response:
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
    "blacklist": false,
    "proxy": false
  }
}
```

### Batch Check
```
POST /check/batch
```

Body:
```json
{
  "tokens": [
    { "chain": "ethereum", "address": "0x..." },
    { "chain": "bsc", "address": "0x..." }
  ]
}
```

## Risk Levels

| Score | Level | Action |
|-------|-------|--------|
| 0-14 | Safe | Low risk |
| 15-34 | Low | Minor concerns |
| 35-54 | Medium | Proceed with caution |
| 55-74 | High | High risk |
| 75-100 | Critical | Avoid |

## Risk Types

- `unverified` - Contract not verified
- `ownership` - Ownership not renounced
- `mintable` - Can mint new tokens
- `pausable` - Can pause transfers
- `blacklist` - Has blacklist function
- `proxy` - Upgradeable contract
- `high_buy_tax` - Buy tax > 10%
- `high_sell_tax` - Sell tax > 10%

## Programmatic Usage

```typescript
import { checkToken, analyzeContract } from 'rugcheck-api';

const result = checkToken('0x...', 'ethereum', {
  verified: true,
  renounced: false,
  mintable: true,
  pausable: false,
  blacklist: false,
  proxy: false,
});

console.log('Risk Score:', result.riskScore);
console.log('Is Honeypot:', result.isHoneypot);
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| PORT | 3001 | Server port |

## License

MIT © [ClawFi](https://github.com/ClawFiAI)
