import http from "http";
import app from "./app";
import dotenv from "dotenv";
import connectDB from "./configs/db";

dotenv.config();

const startServer = async () => {
  await connectDB();

  const server = http.createServer(app);

  const PORT = process.env.PORT || 5000;

  server.listen(PORT, () => {
    console.log(`Server is listening on port ${PORT}`);
  });
};

startServer().catch((err) => {
  console.error("Error starting server", err);
  process.exit(1);
});
