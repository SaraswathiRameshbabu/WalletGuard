import { createPublicClient, http } from "viem";
import { mainnet } from "viem/chains";

const apiKey = process.env.ALCHEMY_API_KEY;

if (!apiKey) {
  throw new Error("ALCHEMY_API_KEY is not configured");
}

export const ethereum = createPublicClient({
  chain: mainnet,
  transport: http(
    `https://eth-mainnet.g.alchemy.com/v2/${apiKey}`
  ),
});