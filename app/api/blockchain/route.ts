import { NextResponse } from "next/server";
import { ethereum } from "@/lib/ethereum";

export async function GET() {
  try {
    const latestBlock = await ethereum.getBlockNumber();

    return NextResponse.json({
      success: true,
      network: "Ethereum Mainnet",
      chainId: 1,
      latestBlock: latestBlock.toString(),
    });
  } catch (error) {
    console.error("Blockchain API error:", error);

    return NextResponse.json(
      {
        success: false,
        error: "Ethereum connection failed",
      },
      {
        status: 500,
      }
    );
  }
}