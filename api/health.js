// Vercel serverless adapter — health / info.
module.exports = (req, res) => {
  const envVal = (k) => process.env[k] || '';
  res.status(200).json({
    ok: true,
    service: 'hanzzz-agent-games',
    tracks: ['proof-gatekeeper', 'steal-the-vfy'],
    hmacConfigured: Boolean(envVal('AGENT_GAMES_HMAC_SECRET')),
    stealConfigured: Boolean(envVal('STEAL_STRATEGY_PARAMS') && envVal('STEAL_STRATEGY_SALT')),
    endpoints: { gatekeeper: '/api/gatekeeper', steal: '/api/steal' },
  });
};
