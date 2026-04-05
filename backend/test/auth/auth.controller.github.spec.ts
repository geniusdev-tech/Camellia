import { AuthController } from '../../nest-src/modules/auth/auth.controller';

describe('AuthController GitHub OAuth', () => {
  const baseEnv = { ...process.env };

  afterEach(() => {
    process.env = { ...baseEnv };
  });

  it('redirects without leaking token in query string and sets temporary oauth cookie', async () => {
    process.env.ALLOWED_ORIGIN = 'http://localhost:3000,http://127.0.0.1:3000';
    const authService = {
      githubLogin: jest.fn().mockResolvedValue({ accessToken: 'jwt.token.value' }),
    };
    const controller = new AuthController(authService as never);

    const req = {
      secure: true,
      headers: { 'x-forwarded-proto': 'https' },
      user: { id: 'u-1' },
    } as any;
    const res = {
      cookie: jest.fn(),
      clearCookie: jest.fn(),
      redirect: jest.fn(),
    } as any;

    await controller.githubAuthCallback(req, res);

    expect(res.cookie).toHaveBeenCalledWith(
      'gatestack_oauth_token',
      expect.any(String),
      expect.objectContaining({
        httpOnly: true,
        secure: true,
        sameSite: 'none',
      }),
    );
    expect(res.redirect).toHaveBeenCalledWith('http://localhost:3000/login?oauth=success');
    expect(String(res.redirect.mock.calls[0][0])).not.toContain('token=');
  });

  it('exchanges temporary oauth cookie into access token', async () => {
    const authService = { githubLogin: jest.fn() };
    const controller = new AuthController(authService as never);

    const req = {
      secure: true,
      headers: { cookie: 'gatestack_oauth_token=abc123; other=1', 'x-forwarded-proto': 'https' },
    } as any;
    const json = jest.fn();
    const res = {
      clearCookie: jest.fn(),
      status: jest.fn().mockReturnValue({ json }),
      json: jest.fn(),
    } as any;

    await controller.githubSession(req, res);

    expect(res.clearCookie).toHaveBeenCalledWith(
      'gatestack_oauth_token',
      expect.objectContaining({ httpOnly: true }),
    );
    expect(res.json).toHaveBeenCalledWith({ success: true, accessToken: 'abc123' });
  });
});
