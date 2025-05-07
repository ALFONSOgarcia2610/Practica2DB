const bcrypt = require('bcrypt');

const hashPassword = async (plainTextPassword) => {
    const saltRounds = 10;
    const salt = await bcrypt.genSalt(saltRounds);
    const hashedPassword = await bcrypt.hash(plainTextPassword, salt);
    return hashedPassword;
};

module.exports = hashPassword;