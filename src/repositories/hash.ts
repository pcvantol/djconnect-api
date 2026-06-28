import { sha256Hex } from "../crypto";

export async function stableHashPrefix(value: string): Promise<string> {
	return (await sha256Hex(value)).slice(0, 16);
}
