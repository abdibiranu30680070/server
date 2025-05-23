const userServices = require("../Service/userService");
const auth = require("../middleware/auth");

const login = async (req, res) => {
  try {
    const { email, password } = req.body;

    // Validate input
    if (!email || !password) {
      return res.status(400).json({ error: "Email and password required" });
    }

    // Find user
    const user = await userServices.checkIfFound(email);
    if (!user) {
      return res.status(404).json({ error: "User not found. Please signup" });
    }

    // Verify credentials
    const validPassword = await userServices.verifyPassword(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    // Define allowed admin roles
    const adminRoles = ["superadmin", "admin", "moderator"];
    
    // Assign default role if not provided
    const userRole = adminRoles.includes(user.role) ? user.role : "user";

    // Generate token
    const token = auth.generateToken({
      userId: user.id,
      email: user.email,
      role: userRole
    });

    console.log("Generated Token:", token); // Debugging

    if (!token) {
      return res.status(500).json({ error: "Token generation failed" });
    }

    // Send token to frontend
    res.status(200).json({
      message: "Login successful",
      token,
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        role: userRole
      }
    });

  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
};

const register = async (req, res) => {
  try {
    const { email, name, password, role } = req.body;

    console.log("Received data:", { email, name, password, role }); // Debugging

    // Validate input
    if (!email || !name || !password) {
      return res.status(400).json({ error: "All fields are required" });
    }

    // Check existing user
    const existingUser = await userServices.checkIfFound(email);
    if (existingUser) {
      return res.status(409).json({ error: "User already exists" });
    }

    // Define allowed admin roles
    const adminRoles = ["superadmin", "admin", "moderator"];
    
    // Assign role, defaulting to "user" if not an admin role
    const userRole = adminRoles.includes(role) ? role : "user";

    // Create new user
    const newUser = await userServices.registerUser(email, name, password, userRole);

    // Token generation and response
    const token = auth.generateToken({
      userId: newUser.id,
      email: newUser.email,
      role: userRole
    });

    res.status(201).json({
      message: "Registration successful",
      user: {
        id: newUser.id,
        email: newUser.email,
        name: newUser.name,
        role: userRole
      },
      token
    });

  } catch (error) {
    console.error("Registration error:", error);
    res.status(500).json({ error: error.message || "Registration failed" });
  }
};

// In authController.js - Add these new controllers
const forgotPassword = async (req, res) => {
  try {
    const { email } = req.body;
    const result = await userServices.initiatePasswordReset(email);
    res.status(200).json(result);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
};

const resetPassword = async (req, res) => {
  try {
    const { token, email, newPassword } = req.body;
    
    // Verify token first
    await userServices.verifyPasswordResetToken(token, email);
    
    // Update password
    const result = await userServices.updateUserPassword(email, newPassword);
    res.status(200).json(result);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
};

// Update module exports
module.exports = {
  register,
  login,
  forgotPassword,
  resetPassword
};