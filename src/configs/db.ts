import mongoose from "mongoose";

const connectDB = async () => {
  try {
    await mongoose.connect(process.env.MONGO_URI!);
    console.log("MongoDb Connected Successfully");
  } catch (error) {
    console.error("MongoDB Connection Error!");
    process.exit(1);
  }
};

export default connectDB;
