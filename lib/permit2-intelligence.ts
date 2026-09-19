import type { Address } from "viem";

export const PERMIT2_ADDRESS =
  "0x000000000022d473030f116ddee9f6b43ac78ba3" as Address;

export type Permit2Intelligence = {
  isPermit2: boolean;

  baseApprovalVerified: boolean;

  internalPermissionFound: boolean;

  spender: Address | null;

  amount: string | null;

  expiration: number | null;

  nonce: number | null;

  reason: string | null;
};

type BuildPermit2IntelligenceParams = {
  spender: Address;
  baseApprovalVerified: boolean;

  internalPermission?: {
    spender: Address;
    amount: bigint;
    expiration: number;
    nonce: number;
  } | null;
};

function sameAddress(
  first: string,
  second: string
): boolean {
  return first.toLowerCase() === second.toLowerCase();
}

export function buildPermit2Intelligence({
  spender,
  baseApprovalVerified,
  internalPermission = null,
}: BuildPermit2IntelligenceParams): Permit2Intelligence {
  const isPermit2 = sameAddress(
    spender,
    PERMIT2_ADDRESS
  );

  if (!isPermit2) {
    return {
      isPermit2: false,

      baseApprovalVerified,

      internalPermissionFound: false,

      spender: null,

      amount: null,

      expiration: null,

      nonce: null,

      reason: null,
    };
  }

  if (internalPermission) {
    return {
      isPermit2: true,

      baseApprovalVerified,

      internalPermissionFound: true,

      spender: internalPermission.spender,

      amount: internalPermission.amount.toString(),

      expiration:
        internalPermission.expiration,

      nonce: internalPermission.nonce,

      reason: null,
    };
  }

  return {
    isPermit2: true,

    baseApprovalVerified,

    internalPermissionFound: false,

    spender: null,

    amount: null,

    expiration: null,

    nonce: null,

    reason:
      "The ERC-20 approval to Uniswap Permit2 is verified on-chain, but no specific internal Permit2 permission could be established from the available scanned evidence.",
  };
}