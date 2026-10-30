import express, { Request, Response } from 'express';
import _ from 'lodash';

const app = express();
app.use(express.json());

app.post('/settings', (req: Request, res: Response) => {
  const defaults = { theme: 'light' };
  // Request body merged into defaults with lodash: the vulnerable call.
  res.json(_.defaultsDeep(req.body, defaults));
});

export default app;
