import { Response } from 'express';

export function renderResults(res: Response, q: string) {
  res.send(`<h1>Search results for ${q}</h1>`); // EVAL-SINK
}
