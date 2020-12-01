import { RCON } from '../rcon.ts';

const rcon = new RCON();

await rcon.connect('127.0.0.1', 19132, 'Password123');

await rcon.send('say hello', 'COMMAND');
