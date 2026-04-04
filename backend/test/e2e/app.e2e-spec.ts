import request from 'supertest';
import { createE2eApp, closeE2eApp, type E2eContext } from './setup';

describe('App E2E', () => {
  let ctx: E2eContext;
  let accessToken = '';

  beforeAll(async () => {
    ctx = await createE2eApp();
  });

  afterAll(async () => {
    await closeE2eApp(ctx);
  });

  it('GET /health returns 200 and status ok', async () => {
    const response = await request(ctx.app.getHttpServer()).get('/health');

    expect(response.status).toBe(200);
    expect(response.body).toEqual(
      expect.objectContaining({
        status: 'ok',
        service: 'gatestack-backend',
      }),
    );
    expect(typeof response.body.timestamp).toBe('string');
  });

  it('POST /api/auth/login returns access token', async () => {
    const response = await request(ctx.app.getHttpServer()).post('/api/auth/login').send({
      email: 'admin@gatestack.local',
      password: 'ChangeMeNow_12345',
    });

    expect(response.status).toBe(201);
    expect(response.body.success).toBe(true);
    expect(typeof response.body.accessToken).toBe('string');
    accessToken = response.body.accessToken;
  });

  it('GET /api/releases without token returns 401', async () => {
    const response = await request(ctx.app.getHttpServer()).get('/api/releases');
    expect(response.status).toBe(401);
  });

  it('POST /api/releases with token creates release', async () => {
    const response = await request(ctx.app.getHttpServer())
      .post('/api/releases')
      .set('Authorization', `Bearer ${accessToken}`)
      .send({
        packageName: 'e2e-lib',
        packageVersion: '1.0.0',
        releaseChannel: 'stable',
        deploymentEnv: 'prod',
        maxCvss: 4.2,
        complianceScore: 80,
        riskScore: 20,
      });

    expect(response.status).toBe(201);
    expect(response.body.success).toBe(true);
    expect(response.body.release.packageName).toBe('e2e-lib');
  });

  it('GET /metrics without token returns 403', async () => {
    const response = await request(ctx.app.getHttpServer()).get('/metrics');
    expect(response.status).toBe(403);
  });

  it('GET /metrics with token returns prometheus payload', async () => {
    const response = await request(ctx.app.getHttpServer())
      .get('/metrics')
      .set('x-metrics-token', 'test_metrics_token_123456');

    expect(response.status).toBe(200);
    expect(response.text).toContain('gatestack_http_requests_total');
  });
});
