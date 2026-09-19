import {
  buildSecurityIntelligence,
  type SecurityIntelligence,
} from "@/lib/security-intelligence";

import {
  buildPermit2Intelligence,
  type Permit2Intelligence,
} from "@/lib/permit2-intelligence";
import { NextRequest, NextResponse } from "next/server";
import {
  decodeFunctionData,
  formatUnits,
  isAddress,
  type Address,
} from "viem";

import { ethereum } from "@/lib/ethereum";

const APPROVE_SELECTOR = "0x095ea7b3";

const approvalAbi = [
  {
    type: "function",
    name: "approve",
    stateMutability: "nonpayable",
    inputs: [
      {
        name: "spender",
        type: "address",
      },
      {
        name: "amount",
        type: "uint256",
      },
    ],
    outputs: [
      {
        name: "",
        type: "bool",
      },
    ],
  },
] as const;

const erc20ReadAbi = [
  {
    type: "function",
    name: "allowance",
    stateMutability: "view",
    inputs: [
      {
        name: "owner",
        type: "address",
      },
      {
        name: "spender",
        type: "address",
      },
    ],
    outputs: [
      {
        name: "",
        type: "uint256",
      },
    ],
  },
  {
    type: "function",
    name: "balanceOf",
    stateMutability: "view",
    inputs: [
      {
        name: "account",
        type: "address",
      },
    ],
    outputs: [
      {
        name: "",
        type: "uint256",
      },
    ],
  },
  {
    type: "function",
    name: "decimals",
    stateMutability: "view",
    inputs: [],
    outputs: [
      {
        name: "",
        type: "uint8",
      },
    ],
  },
  {
    type: "function",
    name: "symbol",
    stateMutability: "view",
    inputs: [],
    outputs: [
      {
        name: "",
        type: "string",
      },
    ],
  },
] as const;


const KNOWN_SPENDERS: Record<
  string,
  {
    name: string;
    category: "PROTOCOL" | "INFRASTRUCTURE";
  }
> = {
  "0x7a250d5630b4cf539739df2c5dacb4c659f2488d": {
    name: "Uniswap V2 Router",
    category: "PROTOCOL",
  },

  "0xe592427a0aece92de3edee1f18e0157c05861564": {
    name: "Uniswap V3 SwapRouter",
    category: "PROTOCOL",
  },

  "0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45": {
    name: "Uniswap SwapRouter02",
    category: "PROTOCOL",
  },

  "0x66a9893cc07d91d95644aedd05d03f95e1dba8af": {
    name: "Uniswap Universal Router",
    category: "PROTOCOL",
  },

  "0x000000000022d473030f116ddee9f6b43ac78ba3": {
    name: "Uniswap Permit2",
    category: "INFRASTRUCTURE",
  },
};


type Risk =
  | "HIGH"
  | "REVIEW"
  | "LOW"
  | "NO_EXPOSURE";

type SpenderClassification =
  | "UNKNOWN"
  | "KNOWN_PROTOCOL"
  | "KNOWN_INFRASTRUCTURE";

type Finding = {
  token: Address;

  tokenSymbol: string;

  tokenDecimals: number;

  spender: Address;

  spenderLabel: string;

  spenderClassification: SpenderClassification;

  allowance: string;

  allowanceFormatted: string;

  walletBalance: string;

  walletBalanceFormatted: string;

  currentExposure: string;

  currentExposureFormatted: string;

  unlimited: boolean;

  approvalTransactionHash: string;

  approvalBlockNumber: string;

  approvalTimestamp: string | null;

  status: "ACTIVE";

  risk: Risk;

    riskVector: {
    permission: "HIGH" | "MEDIUM" | "LOW";

    assetExposure:
      | "HIGH"
      | "MEDIUM"
      | "LOW"
      | "NONE";

    spenderRisk:
      | "HIGH"
      | "MEDIUM"
      | "LOW";

    activityRisk:
      | "HIGH"
      | "MEDIUM"
      | "LOW"
      | "UNKNOWN";

    contractRisk:
      | "UNKNOWN"
      | "KNOWN";

    dataConfidence:
      | "HIGH"
      | "MEDIUM"
      | "LOW";
  };

  securityIntelligence?: SecurityIntelligence;
  permit2Intelligence?: Permit2Intelligence;

  explanation: string;
};

type Candidate = {
  token: Address;

  spender: Address;

  transactionHash: string;

  blockNumber: string;

  timestamp: string | null;
};


const scanCache = new Map<
  string,
  {
    expires: number;
    data: unknown;
  }
>();

const scanInFlight = new Map<
  string,
  Promise<unknown>
>();

const CACHE_MS = 20_000;


function getSpenderInfo(spender: Address) {
  const known =
    KNOWN_SPENDERS[
      spender.toLowerCase()
    ];

  if (!known) {
    return {
      name: "Unknown Contract",

      classification:
        "UNKNOWN" as const,
    };
  }

  return {
    name: known.name,

    classification:
      known.category ===
      "INFRASTRUCTURE"
        ? ("KNOWN_INFRASTRUCTURE" as const)
        : ("KNOWN_PROTOCOL" as const),
  };
}


function isUnlimitedAllowance(
  value: bigint
) {
  /*
   * Treat very large uint256 approvals as
   * effectively unlimited.
   */
  return value >= 2n ** 128n;
}


function formatTokenAmount(
  value: bigint,
  decimals: number
) {
  try {
    return formatUnits(
      value,
      decimals
    );
  } catch {
    return value.toString();
  }
}

function parseTimestamp(
  value: unknown
) {
  const numericValue =
    Number(value);

  if (
    !Number.isFinite(
      numericValue
    )
  ) {
    return null;
  }

  return new Date(
    numericValue * 1000
  ).toISOString();
}


function classifyFinding(
  exposure: bigint,
  balance: bigint,
  allowance: bigint,
  unlimited: boolean,
  spender: Address,
  securityIntelligence: SecurityIntelligence
) {
  const info = getSpenderInfo(spender);

  let permission: "HIGH" | "MEDIUM" | "LOW";
  if (unlimited) {
    permission = "HIGH";
  } else if (balance > 0n && allowance * 2n >= balance) {
    permission = "MEDIUM";
  } else {
    permission = "LOW";
  }

  let assetExposure: "HIGH" | "MEDIUM" | "LOW" | "NONE";
  if (exposure === 0n) {
    assetExposure = "NONE";
  } else if (balance > 0n) {
    const exposurePercent = (exposure * 100n) / balance;
    assetExposure = exposurePercent >= 75n
      ? "HIGH"
      : exposurePercent >= 25n
        ? "MEDIUM"
        : "LOW";
  } else {
    assetExposure = "NONE";
  }

  const spenderRisk: "HIGH" | "MEDIUM" | "LOW" =
    info.classification === "UNKNOWN"
      ? "HIGH"
      : info.classification === "KNOWN_INFRASTRUCTURE"
        ? "MEDIUM"
        : "LOW";

  let activityRisk: "HIGH" | "MEDIUM" | "LOW" | "UNKNOWN";
  if (securityIntelligence.activityStatus === "UNKNOWN") {
    activityRisk = "UNKNOWN";
  } else if (securityIntelligence.activityStatus === "NO_INTERACTION_FOUND") {
    activityRisk = "LOW";
  } else if (securityIntelligence.lastSpenderInteraction) {
    const ageDays = Math.max(
      0,
      Math.floor(
        (Math.floor(Date.now() / 1000) - securityIntelligence.lastSpenderInteraction) /
          86_400
      )
    );
    activityRisk = ageDays <= 30 ? "HIGH" : "MEDIUM";
  } else {
    activityRisk = "UNKNOWN";
  }

  const contractRisk = info.classification === "UNKNOWN" ? "UNKNOWN" as const : "KNOWN" as const;
  const dataConfidence = securityIntelligence.activityStatus === "UNKNOWN" ? "MEDIUM" as const : "HIGH" as const;

  const riskVector = {
    permission,
    assetExposure,
    spenderRisk,
    activityRisk,
    contractRisk,
    dataConfidence,
  };

  if (exposure === 0n) {
    return {
      spenderName: info.name,
      spenderClassification: info.classification,
      risk: "NO_EXPOSURE" as const,
      riskVector,
      explanation:
        "The approval remains live, but the wallet currently has no token balance exposed through it. The permission is still active and should be reconsidered if the token balance becomes non-zero.",
    };
  }

  if (info.classification === "KNOWN_INFRASTRUCTURE") {
    return {
      spenderName: info.name,
      spenderClassification: info.classification,
      risk: "REVIEW" as const,
      riskVector,
      explanation:
        "The ERC-20 approval to Uniswap Permit2 is verified on-chain. Permit2 is recognized infrastructure, but WalletGuard does not yet enumerate its internal spender, amount, expiration, and nonce permissions from the available evidence.",
    };
  }

  if (info.classification === "UNKNOWN" && unlimited) {
    return {
      spenderName: info.name,
      spenderClassification: info.classification,
      risk: "HIGH" as const,
      riskVector,
      explanation:
        "The wallet has live token exposure behind an effectively unlimited approval to an unknown contract. The combination of broad permission, current exposure, and limited spender identity evidence requires close review.",
    };
  }

  if (info.classification === "UNKNOWN") {
    return {
      spenderName: info.name,
      spenderClassification: info.classification,
      risk: "REVIEW" as const,
      riskVector,
      explanation:
        "The wallet has live token exposure behind an approval to an unknown contract. Review the spender before keeping the permission.",
    };
  }

  if (unlimited) {
    return {
      spenderName: info.name,
      spenderClassification: info.classification,
      risk: "REVIEW" as const,
      riskVector,
      explanation:
        `${info.name} is recognized protocol infrastructure, but the wallet has an effectively unlimited approval with live balance exposure.`,
    };
  }

  return {
    spenderName: info.name,
    spenderClassification: info.classification,
    risk: "LOW" as const,
    riskVector,
    explanation:
      `${info.name} is recognized protocol infrastructure and the current exposure is limited by the live allowance.`,
  };
}


async function fetchTransactions(
  wallet: Address
) {
  const transactions: any[] = [];


  for (
    let page = 1;
    page <= 5;
    page++
  ) {
    const url =
      "https://api.routescan.io/v2/network/mainnet/evm/1/etherscan/api" +
      `?module=account` +
      `&action=txlist` +
      `&address=${wallet}` +
      `&page=${page}` +
      `&offset=1000` +
      `&sort=desc`;

    const response =
      await fetch(url, {
        cache: "no-store",
      });

    if (!response.ok) {
      throw new Error(
        `Routescan returned HTTP ${response.status}.`
      );
    }

    const payload =
      await response.json();

    if (
      !Array.isArray(
        payload.result
      )
    ) {
      break;
    }

    transactions.push(
      ...payload.result
    );

    /*
     * Last page reached.
     */
    if (
      payload.result.length <
      1000
    ) {
      break;
    }
  }

  return transactions;
}

function extractApprovalCandidates(
  transactions: any[],
  wallet: Address
): Candidate[] {
  const latest =
    new Map<
      string,
      Candidate
    >();

  for (const transaction of transactions) {
    
    if (
      String(
        transaction.from || ""
      ).toLowerCase() !==
      wallet.toLowerCase()
    ) {
      continue;
    }

    const input =
      String(
        transaction.input || ""
      );

    
    if (
      !input
        .toLowerCase()
        .startsWith(
          APPROVE_SELECTOR
        )
    ) {
      continue;
    }

    try {
      const decoded =
        decodeFunctionData({
          abi: approvalAbi,

          data:
            input as `0x${string}`,
        });

      const token =
        transaction.to as Address;

      const spender =
        decoded.args[0] as Address;

      if (
        !isAddress(token) ||
        !isAddress(spender)
      ) {
        continue;
      }

      const key =
        `${token.toLowerCase()}:${spender.toLowerCase()}`;

      
      if (!latest.has(key)) {
        latest.set(key, {
          token,

          spender,

          transactionHash:
            String(
              transaction.hash ||
                ""
            ),

          blockNumber:
            String(
              transaction.blockNumber ??
                ""
            ),

          timestamp:
            parseTimestamp(
              transaction.timeStamp ??
                transaction.timestamp
            ),
        });
      }
    } catch {
     
    }
  }

  return [
    ...latest.values(),
  ];
}


async function buildScan(
  wallet: Address
) {

  const transactions =
    await fetchTransactions(
      wallet
    );

  const candidates =
    extractApprovalCandidates(
      transactions,
      wallet
    );

  const findings: Finding[] =
    [];


  const BATCH_SIZE = 50;


  for (
    let start = 0;
    start < candidates.length;
    start += BATCH_SIZE
  ) {
    const batch =
      candidates.slice(
        start,
        start + BATCH_SIZE
      );

    const contracts =
      batch.flatMap(
        (candidate) => [
          {
            address:
              candidate.token,

            abi: erc20ReadAbi,

            functionName:
              "allowance" as const,

            args: [
              wallet,
              candidate.spender,
            ] as const,
          },

          {
            address:
              candidate.token,

            abi: erc20ReadAbi,

            functionName:
              "balanceOf" as const,

            args: [
              wallet,
            ] as const,
          },

          {
            address:
              candidate.token,

            abi: erc20ReadAbi,

            functionName:
              "decimals" as const,
          },

          {
            address:
              candidate.token,

            abi: erc20ReadAbi,

            functionName:
              "symbol" as const,
          },
        ]
      );

    const results =
      await ethereum.multicall({
        contracts,

        allowFailure: true,
      });

    for (
      let index = 0;
      index < batch.length;
      index++
    ) {
      const candidate =
        batch[index];

      const resultIndex =
        index * 4;

      const allowanceResult =
        results[
          resultIndex
        ];

      const balanceResult =
        results[
          resultIndex + 1
        ];

      const decimalsResult =
        results[
          resultIndex + 2
        ];

      const symbolResult =
        results[
          resultIndex + 3
        ];


      if (
        allowanceResult.status !==
          "success" ||
        balanceResult.status !==
          "success"
      ) {
        continue;
      }

      const allowance =
        allowanceResult.result as bigint;

      const balance =
        balanceResult.result as bigint;

    
      if (
        allowance === 0n
      ) {
        continue;
      }

      const decimals =
        decimalsResult.status ===
        "success"
          ? Number(
              decimalsResult.result
            )
          : 18;

      const symbol =
        symbolResult.status ===
        "success"
          ? String(
              symbolResult.result
            ).trim() || "ERC20"
          : "ERC20";


      const currentExposure =
        allowance < balance
          ? allowance
          : balance;

      const unlimited =
        isUnlimitedAllowance(
          allowance
        );

      const securityIntelligence =
        buildSecurityIntelligence({
          wallet,
          spender: candidate.spender,
          approvalTimestamp:
            candidate.timestamp
              ? Math.floor(
                  new Date(candidate.timestamp).getTime() / 1000
                )
              : null,
          transactions,
          historyLimitReached: transactions.length >= 5000,
        });

      const classification =
        classifyFinding(
          currentExposure,
          balance,
          allowance,
          unlimited,
          candidate.spender,
          securityIntelligence
        );

      findings.push({
        token:
          candidate.token,

        tokenSymbol:
          symbol,

        tokenDecimals:
          decimals,

        spender:
          candidate.spender,

        spenderLabel:
          classification.spenderName,

        spenderClassification:
          classification.spenderClassification,

        allowance:
          allowance.toString(),

        allowanceFormatted:
          formatTokenAmount(
            allowance,
            decimals
          ),

        walletBalance:
          balance.toString(),

        walletBalanceFormatted:
          formatTokenAmount(
            balance,
            decimals
          ),

        currentExposure:
          currentExposure.toString(),

        currentExposureFormatted:
          formatTokenAmount(
            currentExposure,
            decimals
          ),

        unlimited,

        approvalTransactionHash:
          candidate.transactionHash,

        approvalBlockNumber:
          candidate.blockNumber,

        approvalTimestamp:
          candidate.timestamp,

        status: "ACTIVE",

        risk:
          classification.risk,

        riskVector:
          classification.riskVector,

        securityIntelligence,

        permit2Intelligence:
          buildPermit2Intelligence({
            spender: candidate.spender,
            baseApprovalVerified: true,
          }),

        explanation:
          classification.explanation,
      });
    }
  }


  const priority: Record<
    Risk,
    number
  > = {
    HIGH: 4,
    REVIEW: 3,
    LOW: 2,
    NO_EXPOSURE: 1,
  };

  findings.sort(
    (a, b) => {
      const riskDifference =
        priority[b.risk] -
        priority[a.risk];

      if (
        riskDifference !== 0
      ) {
        return riskDifference;
      }

      const exposureA =
        BigInt(
          a.currentExposure
        );

      const exposureB =
        BigInt(
          b.currentExposure
        );

      if (
        exposureA ===
        exposureB
      ) {
        return 0;
      }

      return exposureB >
        exposureA
        ? 1
        : -1;
    }
  );


  const summary = {
    totalActive:
      findings.length,

    high:
      findings.filter(
        (finding) =>
          finding.risk === "HIGH"
      ).length,

    review:
      findings.filter(
        (finding) =>
          finding.risk === "REVIEW"
      ).length,

    low:
      findings.filter(
        (finding) =>
          finding.risk === "LOW"
      ).length,

    noExposure:
      findings.filter(
        (finding) =>
          finding.risk ===
          "NO_EXPOSURE"
      ).length,
  };


  return {
    success: true,

    schemaVersion: 4,

    network:
      "Ethereum Mainnet",

    chainId: 1,

    wallet,

    scannedTransactions:
      transactions.length,

    approvalTransactions:
      candidates.length,

    uniqueApprovalRelationships:
      candidates.length,

    activeApprovals:
      findings.length,

    summary,


    topFindings:
      findings,

    scanInfo: {
      source:
        "Routescan transaction history + Ethereum Mainnet RPC",

      liveStateVerified:
        true,

      exposureFormula:
        "min(live allowance, wallet token balance)",

      historicalTransactionLimit:
        5000,

      usdPricing:
        false,

      usdPricingNote:
        "Exposure is reported in token units. No USD value is inferred without a verified price source.",

      permit2Note:
        "ERC-20 approval to Uniswap Permit2 is classified as known infrastructure. Internal Permit2 permissions are not yet enumerated.",

      activeApprovalDefinition:
        "Historical approve() relationship whose current allowance is greater than zero.",

      evidenceDefinition:
        "Approval transaction plus current allowance, balance, exposure, and available historical spender-activity evidence.",

      riskVectorDefinition:
        "Permission, asset exposure, spender identity, historical activity, contract recognition, and evidence completeness are calculated per approval.",
    },
  };
}


export async function GET(
  request: NextRequest
) {
  try {
    const searchParams =
      new URL(request.url)
        .searchParams;

    const address =
      searchParams.get(
        "address"
      );

    const verifyToken =
      searchParams.get(
        "verifyToken"
      );

    const verifySpender =
      searchParams.get(
        "verifySpender"
      );

    const force =
      searchParams.get(
        "force"
      ) === "1";



    if (
      !address ||
      !isAddress(address)
    ) {
      return NextResponse.json(
        {
          success: false,

          error:
            "A valid Ethereum wallet address is required.",
        },
        {
          status: 400,
        }
      );
    }

    const wallet =
      address as Address;


    if (
      verifyToken &&
      verifySpender &&
      isAddress(
        verifyToken
      ) &&
      isAddress(
        verifySpender
      )
    ) {
      const allowance =
        await ethereum.readContract(
          {
            address:
              verifyToken as Address,

            abi: erc20ReadAbi,

            functionName:
              "allowance",

            args: [
              wallet,

              verifySpender as Address,
            ],
          }
        );

      return NextResponse.json({
        success: true,

        verification: {
          wallet,

          token:
            verifyToken as Address,

          spender:
            verifySpender as Address,

          allowance:
            allowance.toString(),

          revoked:
            allowance === 0n,

          verifiedAt:
            new Date().toISOString(),
        },
      });
    }


    const cacheKey =
      wallet.toLowerCase();

    const cached =
      scanCache.get(
        cacheKey
      );

    if (
      !force &&
      cached &&
      cached.expires >
        Date.now()
    ) {
      return NextResponse.json(
        cached.data
      );
    }


    let scanPromise =
      scanInFlight.get(
        cacheKey
      );

    if (!scanPromise) {
      scanPromise =
        buildScan(wallet)
          .then((data) => {
            scanCache.set(
              cacheKey,
              {
                expires:
                  Date.now() +
                  CACHE_MS,

                data,
              }
            );

            scanInFlight.delete(
              cacheKey
            );

            return data;
          })
          .catch((error) => {
            scanInFlight.delete(
              cacheKey
            );

            throw error;
          });

      scanInFlight.set(
        cacheKey,
        scanPromise
      );
    }

    const result =
      await scanPromise;

    return NextResponse.json(
      result
    );
  } catch (error) {
    console.error(
      "Wallet approval scan failed:",
      error
    );

    return NextResponse.json(
      {
        success: false,

        error:
          error instanceof Error
            ? error.message
            : "Wallet approval scan failed.",
      },
      {
        status: 500,
      }
    );
  }
}