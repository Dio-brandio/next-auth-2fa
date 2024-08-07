import bcrypt from "bcryptjs";
import type { NextAuthConfig } from "next-auth";
import Credentials from "next-auth/providers/credentials";
import { EncryptJWT, jwtDecrypt } from "jose";
// import Github from "next-auth/providers/github";
// import Google from "next-auth/providers/google";

import { LoginSchema } from "./schemas";
import { getUserByEmail } from "./services/user";

export default {
  providers: [
    // Github({
    //   clientId: process.env.GITHUB_CLIENT_ID,
    //   clientSecret: process.env.GITHUB_CLIENT_SECRET,
    // }),
    // Google({
    //   clientId: process.env.GOOGLE_CLIENT_ID,
    //   clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    // }),
    Credentials({
      async authorize(credentials) {
        const validatedFields = LoginSchema.safeParse(credentials);

        if (validatedFields.success) {
          const { email, password } = validatedFields.data;

          const user = await getUserByEmail(email);
          if (!user || !user.password) return null;

          const passwordsMatch = await bcrypt.compare(password, user.password);

          if (passwordsMatch) return user;
        }

        return null;
      },
    }),
  ],
  session: {
    strategy: 'jwt'
  },
  jwt: {
    async encode({ token, secret }) {
      const tokenSecret = new TextEncoder().encode(secret);
      const encodedToken = new EncryptJWT(token)
        .setProtectedHeader({ alg: 'dir', enc: 'A256GCM' })
      const accessToken: string = await encodedToken
        .setExpirationTime("2h")
        .encrypt(tokenSecret);
      return accessToken;
    },
    async decode({ token, secret }) {
      const { payload } = await jwtDecrypt(token || '', new TextEncoder().encode(secret));
      return payload;
    },
  },
  secret: process.env.NEXTAUTH_SECRET
} satisfies NextAuthConfig;
