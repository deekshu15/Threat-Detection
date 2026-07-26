import {
  confirmSignUp,
  confirmUserAttribute,
  fetchUserAttributes,
  getCurrentUser,
  signIn,
  signOut,
  signUp,
  updateUserAttribute,
} from "aws-amplify/auth";

export const authService = {
  async register(email: string, password: string, name: string) {
    return signUp({
      username: email,
      password,
      options: { userAttributes: { email, name } },
    });
  },

  async confirmRegistration(email: string, code: string) {
    return confirmSignUp({ username: email, confirmationCode: code });
  },

  async login(email: string, password: string) {
    // Amplify permits only one locally stored Cognito user at a time. Clear a
    // stale session left by an earlier browser session before switching users.
    await signOut();

    return signIn({ username: email, password });
  },

  async logout() {
    return signOut();
  },

  async getCurrentUser() {
    try {
      return await getCurrentUser();
    } catch {
      return null;
    }
  },

  async getProfile() {
    const attributes = await fetchUserAttributes();

    return {
      name: attributes.name ?? "",
      email: attributes.email ?? "",
    };
  },

  async updateProfile(name: string, email: string) {
    const attributes = await fetchUserAttributes();
    let emailUpdateRequired = false;

    if (name !== (attributes.name ?? "")) {
      await updateUserAttribute({
        userAttribute: { attributeKey: "name", value: name },
      });
    }

    if (email !== (attributes.email ?? "")) {
      const result = await updateUserAttribute({
        userAttribute: { attributeKey: "email", value: email },
      });
      emailUpdateRequired = result.nextStep.updateAttributeStep === "CONFIRM_ATTRIBUTE_WITH_CODE";
    }

    return { emailUpdateRequired };
  },

  async confirmEmailUpdate(code: string) {
    return confirmUserAttribute({
      userAttributeKey: "email",
      confirmationCode: code,
    });
  },
};
