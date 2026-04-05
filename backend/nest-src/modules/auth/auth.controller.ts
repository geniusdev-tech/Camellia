import { Body, Controller, Get, Post, Req, Res, UseGuards, UsePipes } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { Request, Response } from 'express';
import { ZodValidationPipe } from '../../common/pipes/zod-validation.pipe';
import { AuthService } from './auth.service';
import { JwtAuthGuard } from '../../common/guards/jwt-auth.guard';
import { loginSchema, registerSchema, type LoginInput, type RegisterInput } from './auth.schemas';

@Controller('api/auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  private readCookie(rawCookie: string | undefined, name: string): string | null {
    if (!rawCookie) return null;
    const match = rawCookie
      .split(';')
      .map((part) => part.trim())
      .find((part) => part.startsWith(`${name}=`));
    if (!match) return null;
    return decodeURIComponent(match.slice(name.length + 1));
  }

  private oauthCookieOptions(req: Request) {
    const forwardedProto = String(req.headers['x-forwarded-proto'] || '').toLowerCase();
    const isSecure = req.secure || forwardedProto === 'https';
    const sameSite: 'none' | 'lax' = isSecure ? 'none' : 'lax';
    return {
      httpOnly: true as const,
      secure: isSecure,
      sameSite,
      path: '/' as const,
      maxAge: 2 * 60 * 1000,
    };
  }

  private oauthCookieClearOptions(req: Request) {
    const { httpOnly, secure, sameSite, path } = this.oauthCookieOptions(req);
    return { httpOnly, secure, sameSite, path };
  }

  @Post('login')
  @UsePipes(new ZodValidationPipe(loginSchema))
  async login(@Body() body: LoginInput) {
    const result = await this.authService.login(body);
    return { success: true, ...result };
  }

  @Post('register')
  @UsePipes(new ZodValidationPipe(registerSchema))
  async register(@Body() body: RegisterInput) {
    const result = await this.authService.register(body);
    return { success: true, ...result };
  }

  @Get('github')
  @UseGuards(AuthGuard('github'))
  async githubAuth() {
    // Initiates the GitHub OAuth flow
  }

  @Get('github/callback')
  @UseGuards(AuthGuard('github'))
  async githubAuthCallback(@Req() req: Request, @Res() res: Response) {
    const frontendUrl = process.env.ALLOWED_ORIGIN?.split(',')[0]?.trim() || 'http://localhost:3000';
    const cookieOptions = this.oauthCookieOptions(req);
    const clearOptions = this.oauthCookieClearOptions(req);

    try {
      const { accessToken } = await this.authService.githubLogin(req.user);
      res.cookie('gatestack_oauth_token', accessToken, cookieOptions);
      res.redirect(`${frontendUrl}/login?oauth=success`);
    } catch {
      res.clearCookie('gatestack_oauth_token', clearOptions);
      res.redirect(`${frontendUrl}/login?error=github_oauth_failed`);
    }
  }

  @Get('github/session')
  async githubSession(@Req() req: Request, @Res() res: Response) {
    const clearOptions = this.oauthCookieClearOptions(req);
    const token = this.readCookie(req.headers.cookie, 'gatestack_oauth_token');
    res.clearCookie('gatestack_oauth_token', clearOptions);
    if (!token) {
      return res.status(401).json({ success: false, message: 'GitHub session not found' });
    }
    return res.json({ success: true, accessToken: token });
  }

  @Get('me')
  @UseGuards(JwtAuthGuard)
  async getMe(@Req() req: any) {
    const user = await this.authService.getUserById(req.user.sub);
    return { success: true, user };
  }
}
