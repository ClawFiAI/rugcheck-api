/**
 * Rugcheck API Server
 * Real implementation with GoPlus Security API
 */

import Fastify from 'fastify';
import cors from '@fastify/cors';
import { checkToken, checkTokens, isHoneypot, getSupportedChains } from './index';

const fastify = Fastify({ logger: true });

fastify.register(cors, { origin: true });

// Health check
fastify.get('/health', async () => ({ 
  status: 'ok', 
  timestamp: Date.now(),
  supportedChains: getSupportedChains(),
}));

// Get supported chains
fastify.get('/chains', async () => ({
  chains: getSupportedChains(),
}));

// Check single token
fastify.get<{
  Params: { chain: string; address: string };
}>('/check/:chain/:address', async (request, reply) => {
  const { chain, address } = request.params;
  
  // Validate chain
  if (!getSupportedChains().includes(chain.toLowerCase())) {
    return reply.status(400).send({ 
      error: `Unsupported chain: ${chain}. Supported: ${getSupportedChains().join(', ')}` 
    });
  }
  
  // Validate address format
  if (!/^0x[a-fA-F0-9]{40}$/.test(address)) {
    return reply.status(400).send({ error: 'Invalid address format' });
  }
  
  try {
    const result = await checkToken(address, chain);
    return result;
  } catch (error) {
    fastify.log.error(error);
    return reply.status(500).send({ error: 'Failed to check token' });
  }
});

// Quick honeypot check
fastify.get<{
  Params: { chain: string; address: string };
}>('/honeypot/:chain/:address', async (request, reply) => {
  const { chain, address } = request.params;
  
  if (!getSupportedChains().includes(chain.toLowerCase())) {
    return reply.status(400).send({ error: `Unsupported chain: ${chain}` });
  }
  
  try {
    const result = await isHoneypot(address, chain);
    return { 
      address, 
      chain, 
      isHoneypot: result,
      timestamp: Date.now(),
    };
  } catch (error) {
    fastify.log.error(error);
    return reply.status(500).send({ error: 'Failed to check honeypot' });
  }
});

// Batch check multiple tokens
fastify.post<{
  Body: { tokens: { chain: string; address: string }[] };
}>('/check/batch', async (request, reply) => {
  const { tokens } = request.body;
  
  if (!Array.isArray(tokens) || tokens.length === 0) {
    return reply.status(400).send({ error: 'tokens array required' });
  }
  
  if (tokens.length > 20) {
    return reply.status(400).send({ error: 'Maximum 20 tokens per batch' });
  }
  
  // Validate all tokens
  for (const token of tokens) {
    if (!getSupportedChains().includes(token.chain?.toLowerCase())) {
      return reply.status(400).send({ error: `Unsupported chain: ${token.chain}` });
    }
    if (!/^0x[a-fA-F0-9]{40}$/.test(token.address)) {
      return reply.status(400).send({ error: `Invalid address: ${token.address}` });
    }
  }
  
  try {
    const results = await checkTokens(tokens);
    return { results, count: results.length };
  } catch (error) {
    fastify.log.error(error);
    return reply.status(500).send({ error: 'Failed to check tokens' });
  }
});

// Risk score only (lightweight)
fastify.get<{
  Params: { chain: string; address: string };
}>('/risk/:chain/:address', async (request, reply) => {
  const { chain, address } = request.params;
  
  try {
    const result = await checkToken(address, chain);
    return {
      address,
      chain,
      riskScore: result.riskScore,
      riskLevel: result.riskLevel,
      isHoneypot: result.isHoneypot,
      riskCount: result.risks.length,
      criticalRisks: result.risks.filter(r => r.severity === 'critical').length,
      timestamp: Date.now(),
    };
  } catch (error) {
    fastify.log.error(error);
    return reply.status(500).send({ error: 'Failed to get risk score' });
  }
});

// Start server
const start = async () => {
  try {
    const port = parseInt(process.env.PORT || '3001');
    const host = process.env.HOST || '0.0.0.0';
    
    await fastify.listen({ port, host });
    
    console.log(`
╔══════════════════════════════════════════════════════╗
║             Rugcheck API Server Started              ║
╠══════════════════════════════════════════════════════╣
║  Port: ${port.toString().padEnd(46)}║
║  Supported Chains: ${getSupportedChains().slice(0, 5).join(', ').padEnd(34)}║
║                    ${getSupportedChains().slice(5).join(', ').padEnd(34)}║
╠══════════════════════════════════════════════════════╣
║  Endpoints:                                          ║
║    GET  /check/:chain/:address    Full check         ║
║    GET  /honeypot/:chain/:address Quick honeypot     ║
║    GET  /risk/:chain/:address     Risk score only    ║
║    POST /check/batch              Batch check        ║
║    GET  /chains                   Supported chains   ║
║    GET  /health                   Health check       ║
╚══════════════════════════════════════════════════════╝
    `);
  } catch (err) {
    fastify.log.error(err);
    process.exit(1);
  }
};

start();
