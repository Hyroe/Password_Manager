import express from "express";

export const app = express();

app.disable("x-powered-by");

app.use(
  express.json({
    limit: "2mb",
  }),
);

app.get("/api/v1/health", (_req, res) => {
  res.status(200).json({
    status: "ok",
  });
});
