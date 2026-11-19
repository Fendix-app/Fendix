import { Response } from 'express';

export function redirectAfterLogin(res: Response, returnTo: string) {
  res.redirect(returnTo); // EVAL-SINK
}
