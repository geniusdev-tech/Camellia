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

    try {
      const { accessToken } = await this.authService.githubLogin(req.user);
      const encodedToken = encodeURIComponent(accessToken);
      res.redirect(`${frontendUrl}/login?token=${encodedToken}`);
    } catch {
      res.redirect(`${frontendUrl}/login?error=github_oauth_failed`);
    }
  }

  @Get('me')
  @UseGuards(JwtAuthGuard)
  async getMe(@Req() req: any) {
    const user = await this.authService.getUserById(req.user.sub);
    return { success: true, user };
  }
}
