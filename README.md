# RCON
A basic RCON implementation in Deno

# Usage
The API is very simple. There are two exposed methods on `RCON` class, `connect()` and `send()`.

```ts
import { RCON } from './mod.ts';

const rcon = new RCON();

await rcon.connect('127.0.0.1', 19132, 'Password123');

await rcon.send('say hello', 'COMMAND');

# Credits
TS-RCON - https://github.com/bmiddha/ts-rcon (Part of buffer implementation and non-ASCII character removal was used)
