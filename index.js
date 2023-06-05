// import section
const { ApolloServer, gql } = require("apollo-server");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const mysql = require("mysql2");

// db connection section for mysql db
const connection = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "passwd",
  database: "graphql",
});

connection.connect((err) => {
  if (err) {
    console.error("Error connecting to MySQL:", err);
    return;
  }
  console.log("Connected to MySQL successfully!");
});

// example schema definition for login and getting user details
const typeDefs = gql`
  type User {
    id: ID!
    email: String!
    password: String!
  }

  type Query {
    me: User
  }

  type Mutation {
    register(email: String!, password: String!): User!
    login(email: String!, password: String!): String!
  }
`;

// db connection section for mysql db
const resolvers = {
  Query: {
    me: (parent, args, context) => {
      if (!context) {
        throw new Error("Authentication required");
      }
      return context;
    },
  },
  Mutation: {
    register: async (parent, { email, password }) => {
      const hashedPassword = await bcrypt.hash(password, 10);
      const user = { email, password: hashedPassword };
      const query = "INSERT INTO users (email, password) VALUES (?, ?)";
      const values = [user.email, user.password];

      return new Promise((resolve, reject) => {
        connection.query(query, values, (err, result) => {
          if (err) {
            reject(err);
          } else {
            user.id = result.insertId;
            resolve(user);
          }
        });
      });
    },
    login: async (parent, { email, password }) => {
      const query = "SELECT * FROM users WHERE email = ?";
      const values = [email];

      return new Promise((resolve, reject) => {
        connection.query(query, values, async (err, result) => {
          if (err) {
            reject(err);
          } else if (!result || result.length === 0) {
            reject(new Error("Invalid credentials"));
          } else {
            const user = result[0];
            const validPassword = await bcrypt.compare(password, user.password);
            if (!validPassword) {
              reject(new Error("Invalid credentials"));
            }
            const token = jwt.sign({ userId: user.id }, "topsecret", { expiresIn: "1h" });
            resolve(token);
          }
        });
      });
    },
  },
};

// server config to merge all this to run in local environment
const server = new ApolloServer({
  typeDefs,
  resolvers,
  context: async ({ req }) => {
    const authHeader = req.headers.authorization;
    if (authHeader) {
      const token = authHeader.replace("Bearer ", "");
      const { userId } = jwt.verify(token, "topsecret");
      const query = "SELECT * FROM users WHERE id = ?";
      const values = [userId];

      return new Promise((resolve, reject) => {
        connection.query(query, values, (err, result) => {
          if (err) {
            reject(err);
          } else if (!result || result.length === 0) {
            resolve(null);
          } else {
            const user = result[0];
            resolve(user);
            return user;
          }
        });
      });
    }
    return context;
  },
});

// to run the graphql server
server.listen().then(({ url }) => {
  console.log(`Apollo Server running at ${url}`);
});
