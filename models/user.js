/** User class for message.ly */

const db = require("../db");
const bcrypt = require("bcrypt");
const ExpressError = require("../expressError");

const { BCRYPT_WORK_FACTOR } = require("../config");

/** User of the site. */

class User {

  /** register new user -- returns
   *    {username, password, first_name, last_name, phone}
   */

  static async register({username, password, first_name, last_name, phone}) { 
    let hashedPasswd = await bcrypt.hash(password, BCRYPT_WORK_FACTOR);
    const result = await db.query(`
      INSERT INTO users 
      (username, password, first_name, last_name, phone, join_at, last_login_at)
      VALUES ($1, $2, $3, $4, $5, current_timestamp, current_timestamp)
      RETURNING username, password, first_name, last_name, phone`, 
      [username, hashedPasswd, first_name, last_name, phone]);
      return result.rows[0];
  }
  /** Authenticate: is this username/password valid? Returns boolean. */

  static async authenticate(username, password) { 
    try{
      const result =  await db.query(`SELECT password FROM users WHERE username = $1`, [username]);
      let user = result.rows[0];
      return user && await bcrypt.compare(password, user.password);
    } catch(err){
      throw new ExpressError('Invalid username/password', 401);
    }
  }

  /** Update last_login_at for user */

  static async updateLoginTimestamp(username) { 
    const result = await db.query(`
      UPDATE users SET last_login_at = current_timestamp 
      WHERE username = $1 RETURNING username`, [username]);
    
    if(!result.rows[0]){
      throw new ExpressError(`User ${username} does not exist`, 404);
    } else {
      return result.rows[0];
    }
  }

  /** All: basic info on all users:
   * [{username, first_name, last_name, phone}, ...] */

  static async all() { 
    const result = await db.query(`SELECT username, first_name, last_name, phone FROM users ORDER by username`);
    return result.rows;
  }

  /** Get: get user by username
   *
   * returns {username,
   *          first_name,
   *          last_name,
   *          phone,
   *          join_at,
   *          last_login_at } */

  static async get(username) { 
    const result = await db.query(`SELECT username, first_name, last_name, phone, join_at, last_login_at FROM users WHERE id= $1`,[username]);
    if(!result.rows[0]){
      throw new ExpressError(`User ${username} does not exist`, 404);
    } else {
      return result.rows[0]
    }
  }

  /** Return messages from this user.
   *
   * [{id, to_user, body, sent_at, read_at}]
   *
   * where to_user is
   *   {username, first_name, last_name, phone}
   */

  static async messagesFrom(username) { 
    try{
      const result = await db.query(`
        SELECT msg.id, msg.to_username, u.first_name, u.last_name, u.phone, msg.body, msg.sent_at, msg.read_at 
        FROM messages AS msg JOIN users AS u ON m.to_username = u.username WHERE username = $1`, [username]);
      
      return result.rows.map(m => ({
        id: m.id,
        to_user: {
          username: m.to_username,
          first_name: m.first_name,
          last_name: m.last_name,
          phone: m.phone
        },
        body: m.body,
        sent_at: m.sent_at,
        read_at: m.read_at
      }));

    } catch(err){
      throw new ExpressError(`Unable to retrieve messages from user ${username}`, 404);
    }
    
  }

  /** Return messages to this user.
   *
   * [{id, from_user, body, sent_at, read_at}]
   *
   * where from_user is
   *   {username, first_name, last_name, phone}
   */

  static async messagesTo(username) { 
    try{
      const result = await db.query(
        `SELECT msg.id, msg.from_username, u.first_name, u.last_name, u.phone, msg.body, msg.sent_at, msg.read_at
          FROM messages AS msg
          JOIN users AS u ON msg.from_username = u.username
          WHERE to_username = $1`,[username]);

      return result.rows.map(m => ({
        id: m.id,
        from_user: {
          username: m.from_username,
          first_name: m.first_name,
          last_name: m.last_name,
          phone: m.phone,
          },
        body: m.body,
        sent_at: m.sent_at,
        read_at: m.read_at
    }));
    } catch(err){
      throw new ExpressError(`Unable to retrieve messages to user ${username}`, 404);
    }
  }
}


module.exports = User;