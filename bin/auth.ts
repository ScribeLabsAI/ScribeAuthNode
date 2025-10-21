#! /usr/bin/env node

import { input, password as passwordPrompt } from '@inquirer/prompts';
import { Option, program } from 'commander';
import 'dotenv/config';
import { authenticator } from 'otplib';
import { Auth } from '../src/index.js';

program
  .command('token')
  .description('Get all the JWTs (id, access and refresh) given a user/password pair')
  .addOption(
    new Option('-c, --clientid <clientid>', 'Cognito Client ID')
      .env('CLIENT_ID')
      .makeOptionMandatory(true)
  )
  .addOption(
    new Option('-u, --userpoolid <userpoolid>', 'Cognito User Pool ID')
      .env('USER_POOL_ID')
      .makeOptionMandatory(true)
  )
  .addOption(new Option('-n, --username <username>', 'Username'))
  .addOption(new Option('-p, --password <password>', 'Password'))
  .action(async (options) => {
    const auth = new Auth({
      clientId: options.clientid,
      userPoolId: options.userpoolid,
    });

    // Prompt for username if not provided
    const username =
      options.username ||
      (await input({
        message: 'Enter username:',
      }));

    // Prompt for password if not provided
    const password =
      options.password ||
      (await passwordPrompt({
        message: 'Enter password:',
        mask: true,
      }));

    const result = await auth.getTokens({
      username,
      password,
    });

    // Check if result is a Challenge (MFA required)
    if ('challengeName' in result && 'challengeParameters' in result && 'user' in result) {
      const mfaCode = await input({
        message: 'Enter MFA code:',
      });

      const tokens = await auth.respondToAuthChallengeMfa(
        result.user,
        mfaCode,
        result.challengeParameters
      );
      console.info(tokens);
    } else {
      // Result is already Tokens
      console.info(result);
    }
  });

program
  .command('otp')
  .description('Generate an OTP code given a secret')
  .addOption(
    new Option('-s, --secret <secret>', 'OTP Secret').env('OTPCODE').makeOptionMandatory(true)
  )
  .action((options) => {
    const otpCode = authenticator.generate(options.secret);
    console.info('OTP Code:', otpCode);
  });

program.parse(process.argv);
