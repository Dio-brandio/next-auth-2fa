import nodemailer, { type Transporter } from 'nodemailer';
const transporter: Transporter = nodemailer.createTransport({
  host: "smtp.ethereal.email",
  port: 587,
  secure: false, // Use TLS
  auth: {
    user: "araceli40@ethereal.email",
    pass: "9smuUvSCpaJBt64GRM",
  },
});


const domain = process.env.NEXT_PUBLIC_APP_URL;

export const sendVerificationEmail = async (email: string, token: string) => {
  const confirmLink = `${domain}/auth/new-verification?token=${token}`;

  await transporter.sendMail({
    from: "onboarding@resend.dev",
    to: email,
    subject: "Confirm your email",
    html: `<p>Click <a href="${confirmLink}">here</a> to confirm email.</p>`,
  });
};

export const sendPasswordResetEmail = async (email: string, token: string) => {
  const resetLink = `${domain}/auth/new-password?token=${token}`;

  await transporter.sendMail({
    from: "onboarding@resend.dev",
    to: email,
    subject: "Reset your password",
    html: `<p>Click <a href="${resetLink}">here</a> to reset password.</p>`,
  });
};

export const sendTwoFactorTokenEmail = async (email: string, token: string) => {
  await transporter.sendMail({
    from: "onboarding@resend.dev",
    to: email,
    subject: "2FA Code",
    html: `<p>Your 2FA code: ${token}</p>`,
  });
};
