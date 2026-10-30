import express, { Request, Response } from "express";
import { db } from "./db";

const app = express();

app.get("/items/:id", (req: Request, res: Response) => {
  const id: string = req.params.id;
  db.query(`SELECT * FROM items WHERE id = ${id}`); // SINK:typescript-template
  res.send("ok");
});
