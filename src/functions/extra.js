const bcrypt = require('bcrypt');
const saltRounds = 10;
const { query } = require('../database');

module.exports = {
    
    /**
     * 
     * @param {string} password 
     * @returns {string}
     */
    hashPassword: async (password) => {
        try {
            const hashedPassword = await bcrypt.hash(password, saltRounds);
            return hashedPassword; 
        } catch (err) {
            console.error('Error hashing password:', err);
            throw err;
        }
    },

    /**
     * @param {string} username
     * @param {desc} description
     * @returns {void}
     */
    logAction: async (username, description) => {
        const user = await query('SELECT id FROM users WHERE username = ?', [username]);
        if (user.length > 0) {
            await query('INSERT INTO logs (user_id, username, action_desc) VALUES (?, ?, ?)', [user[0].id, username, description]);
        }
    },

    generatePfp: async (username) => {
        return `https://ui-avatars.com/api/${username}/128?ssl=1`;
    },
    

    /**
     * 
     * @param {string} password 
     * @param {string} storedHash 
     * @returns {boolean}
     */
    comparePassword: async (password, storedHash) => {
        try {
            if (!password || !storedHash) {
                throw new Error('data and hash arguments required');
            }

            const match = await bcrypt.compare(password, storedHash);
            return match;
        } catch (err) {
            console.error('Error comparing passwords:', err);
            throw err;
        }
    },
}