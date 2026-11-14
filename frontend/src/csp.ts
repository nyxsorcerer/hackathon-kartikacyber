// The CSP forbids eval (A15). Unless jitless is set, Zod probes for eval with Function("") when it
// builds an object schema, so main.tsx imports this first, before any module builds one.
import { z } from "zod";
z.config({ jitless: true });
