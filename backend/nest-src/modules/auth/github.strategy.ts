import { Injectable, Logger } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy, Profile } from 'passport-github2';
import { AuthService } from './auth.service';
import { parseEnv } from '../../common/config/env.schema';

@Injectable()
export class GithubStrategy extends PassportStrategy(Strategy, 'github') {
  private readonly logger = new Logger(GithubStrategy.name);

  constructor(private authService: AuthService) {
    const env = parseEnv(process.env);
    const hasGithubOauth =
      Boolean(env.GITHUB_CLIENT_ID && env.GITHUB_CLIENT_ID.trim()) &&
      Boolean(env.GITHUB_CLIENT_SECRET && env.GITHUB_CLIENT_SECRET.trim()) &&
      Boolean(env.GITHUB_CALLBACK_URL && env.GITHUB_CALLBACK_URL.trim());

    if (!hasGithubOauth) {
      throw new Error('GitHub OAuth is not fully configured. Set GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET and GITHUB_CALLBACK_URL.');
    }
    
    super({
      clientID: env.GITHUB_CLIENT_ID!,
      clientSecret: env.GITHUB_CLIENT_SECRET!,
      callbackURL: env.GITHUB_CALLBACK_URL!,
      scope: ['user:email', 'read:user'],
    });
  }

  async validate(accessToken: string, refreshToken: string, profile: Profile, done: (err: any, user: any, info?: any) => void): Promise<any> {
    try {
      this.logger.log(`Github login for: ${profile.username}`);
      
      const user = await this.authService.validateGithubUser({
        githubId: profile.id,
        email: profile.emails?.[0]?.value,
        name: profile.displayName || profile.username,
        avatarUrl: profile.photos?.[0]?.value,
        githubToken: accessToken,
      });

      return done(null, user);
    } catch (error) {
      this.logger.error(error);
      return done(error, false);
    }
  }
}
