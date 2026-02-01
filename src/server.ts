/**
 * Rugcheck API Server
 */

import Fastify from 'fastify';
import cors from '@fastify/cors';
import { checkToken, ContractInfo } from './index';

const fastify = Fastify({ logger: true });

fastify.register(cors, { origin: true });

// Health check
fastify.get('/health', async () => ({ status: 'ok', timestamp: Date.now() }));

// Check token
fastify.get<{
  Params: { chain: string; address: string };
}>('/check/:chain/:address', async (request) => {
  const { chain, address } = request.params;
  
  // Mock contract data - in production, fetch from chain
  const mockContract: ContractInfo = {
    verified: true,
    renounced: false,
    mintable: false,
    pausable: false,
    blacklist: false,
    proxy: false,
  };
  
  return checkToken(address, chain, mockContract);
});

// Batch check
fastify.post<{
  Body: { tokens: { chain: string; address: string }[] };
}>('/check/batch', async (request) => {
  const { tokens } = request.body;
  
  return tokens.map(({ chain, address }) => {
    const mockContract: ContractInfo = {
      verified: true,
      renounced: true,
      mintable: false,
      pausable: false,
      blacklist: false,
      proxy: false,
    };
    return checkToken(address, chain, mockContract);
  });
});

// Start server
const start = async () => {
  try {
    const port = parseInt(process.env.PORT || '3001');
    await fastify.listen({ port, host: '0.0.0.0' });
    console.log(`Rugcheck API running on port ${port}`);
  } catch (err) {
    fastify.log.error(err);
    process.exit(1);
  }
};

start();
