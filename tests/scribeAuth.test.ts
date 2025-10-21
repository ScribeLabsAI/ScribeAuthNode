import { config } from 'dotenv';
import { setTimeout } from 'node:timers/promises';
import { authenticator } from 'otplib';
import { describe, expect, it } from 'vitest';
import {
  Auth,
  Challenge,
  MFAError,
  MissingFieldError,
  Tokens,
  UnauthorizedError,
} from '../src/index.js';

config({ override: true });

const clientId = process.env['CLIENT_ID']!;
const username = process.env['USER']!;
const username2 = process.env['USER2']!;
const password = process.env['PASSWORD']!;
const userPoolId = process.env['USER_POOL_ID']!;
const otp = process.env['OTPCODE']!;
const access = new Auth({ clientId, userPoolId });

describe('Get tokens', () => {
  it('Username and password passes', async () => {
    const tokens = await access.getTokens({ username, password });
    expect(assertTokens(tokens)).toBeTruthy();
  });
  it('Wrong username fails', async () => {
    await expect(() => access.getTokens({ username: 'username', password })).rejects.toThrow(
      UnauthorizedError
    );
  });
  it('Wrong password fails', async () => {
    await expect(() => access.getTokens({ username, password: 'password' })).rejects.toThrow(
      UnauthorizedError
    );
  });

  it('Empty username fails', async () => {
    await expect(() => access.getTokens({ username: '', password })).rejects.toThrow(
      MissingFieldError
    );
  });
  it('Empty password fails', async () => {
    await expect(() => access.getTokens({ username, password: '' })).rejects.toThrow(
      MissingFieldError
    );
  });
  it('Empty username and password fails', async () => {
    await expect(() => access.getTokens({ username: '', password: '' })).rejects.toThrow(
      MissingFieldError
    );
  });
  it('RefreshToken passes', async () => {
    const refreshToken = await getRefreshToken();
    const tokens = await access.getTokens({ refreshToken });
    expect(assertTokens(tokens)).toBeTruthy();
  });
  it('Wrong refreshToken fails', async () => {
    await expect(() => access.getTokens({ refreshToken: 'refresh_token' })).rejects.toThrow(
      UnauthorizedError
    );
  });
});

describe('Get tokens MFA', () => {
  it('asks for MFA', async () => {
    const challenge = await access.getTokens({ username: username2, password });
    if ('challengeName' in challenge && 'challengeParameters' in challenge && 'user' in challenge) {
      expect(challenge.user).toBeDefined();
      expect(challenge.challengeName).toBeDefined();
      expect(challenge.challengeParameters).toBeDefined();
    } else {
      expect(isTokens(challenge)).toBeFalsy();
    }
  });

  it('get tokens with username and password successfully', { timeout: 70_000 }, async () => {
    const challenge = await access.getTokens({ username: username2, password });
    if ('user' in challenge && 'challengeParameters' in challenge) {
      await setTimeout(61_000);
      const code = authenticator.generate(otp);
      const tokens = await access.respondToAuthChallengeMfa(
        challenge.user,
        code,
        challenge.challengeParameters
      );
      expect(assertTokens(tokens)).toBeTruthy();
    } else {
      expect(isTokens(challenge)).toBeFalsy();
    }
  });

  it('get tokens with refresh token successfully', { timeout: 70_000 }, async () => {
    await setTimeout(61_000);
    const refreshToken = await getRefreshTokenWithMFA();
    const tokens = await access.getTokens({ refreshToken });
    expect(assertTokens(tokens)).toBeTruthy();
  });

  it('get tokens fails with wrong mfa code', async () => {
    const challenge = await access.getTokens({ username: username2, password });
    const code = '000000';
    if ('user' in challenge && 'challengeParameters' in challenge) {
      await expect(() =>
        access.respondToAuthChallengeMfa(challenge.user, code, challenge.challengeParameters)
      ).rejects.toThrow(MFAError);
    } else {
      expect(isTokens(challenge)).toBeFalsy();
    }
  });

  it('get tokens fails with expired mfa code', { timeout: 70_000 }, async () => {
    const challenge = await access.getTokens({ username: username2, password });
    const code = authenticator.generate(otp);
    await setTimeout(61_000);
    if ('user' in challenge && 'challengeParameters' in challenge) {
      await expect(() =>
        access.respondToAuthChallengeMfa(challenge.user, code, challenge.challengeParameters)
      ).rejects.toThrow(MFAError);
    } else {
      expect(isTokens(challenge)).toBeFalsy();
    }
  });
});

// RevokeToken is not working yet and we're working on it.
// describe('Revoke', () => {
//   it('Real RefreshToken and passes', async () => {
//     const refreshToken = await getRefreshToken();
//     await expect(() => access.revokeRefreshToken(refreshToken)).toBeTruthy();
//   });
// });

function assertTokens(tokens: Tokens | Challenge): boolean {
  if ('accessToken' in tokens && 'idToken' in tokens && 'refreshToken' in tokens) {
    return (
      !!tokens.accessToken &&
      !!tokens.idToken &&
      !!tokens.refreshToken &&
      tokens.accessToken !== tokens.idToken &&
      tokens.accessToken !== tokens.refreshToken &&
      tokens.idToken !== tokens.refreshToken
    );
  }
  return false;
}

async function getRefreshToken() {
  const tokens = await access.getTokens({ username, password });
  if ('refreshToken' in tokens) {
    return tokens.refreshToken;
  }
  return '';
}

async function getRefreshTokenWithMFA() {
  const challenge = await access.getTokens({ username: username2, password });
  const code = authenticator.generate(otp);
  if ('user' in challenge && 'challengeParameters' in challenge) {
    const response = await access.respondToAuthChallengeMfa(
      challenge.user,
      code,
      challenge.challengeParameters
    );
    return response.refreshToken;
  }
  return '';
}

function isTokens(tokens: Tokens | Challenge) {
  return !!('accessToken' in tokens && 'idToken' in tokens && 'refreshToken' in tokens);
}
