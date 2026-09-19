import type { Address } from "viem";

export type SecurityEvidenceType =
  | "APPROVAL"
  | "SPENDER_INTERACTION"
  | "RECENT_ACTIVITY"
  | "HISTORY_LIMIT";

export type SecurityIntelligence = {
  approvalAgeDays: number | null;

  approvalAgeBand:
    | "RECENT"
    | "ESTABLISHED"
    | "OLD"
    | "UNKNOWN";

  walletInteractedWithSpender: boolean | null;

  spenderInteractionCount: number | null;

  lastSpenderInteraction: number | null;

  activityStatus:
    | "ACTIVE"
    | "NO_INTERACTION_FOUND"
    | "UNKNOWN";

  evidence: Array<{
    type: SecurityEvidenceType;
    description: string;
    timestamp?: number;
    txHash?: string;
  }>;
};

type HistoricalTransaction = {
  hash?: string;
  from?: string;
  to?: string;
  timeStamp?: string | number;
  timestamp?: string | number;
  blockTimestamp?: string | number;
};

type BuildSecurityIntelligenceParams = {
  wallet: Address;
  spender: Address;
  approvalTimestamp?: number | null;
  transactions?: HistoricalTransaction[];
  historyLimitReached?: boolean;
  now?: number;
};

function normalizeAddress(address?: string | null): string {
  return (address ?? "").toLowerCase();
}

function getTimestamp(
  transaction: HistoricalTransaction
): number | null {
  const value =
    transaction.timeStamp ??
    transaction.timestamp ??
    transaction.blockTimestamp;

  if (value === undefined || value === null) {
    return null;
  }

  const numeric = Number(value);

  if (!Number.isFinite(numeric) || numeric <= 0) {
    return null;
  }

  return numeric > 10_000_000_000
    ? Math.floor(numeric / 1000)
    : Math.floor(numeric);
}

function getApprovalAgeBand(
  approvalAgeDays: number | null
): SecurityIntelligence["approvalAgeBand"] {
  if (approvalAgeDays === null) {
    return "UNKNOWN";
  }

  if (approvalAgeDays < 7) {
    return "RECENT";
  }

  if (approvalAgeDays <= 90) {
    return "ESTABLISHED";
  }

  return "OLD";
}

export function buildSecurityIntelligence({
  wallet,
  spender,
  approvalTimestamp,
  transactions = [],
  historyLimitReached = false,
  now = Math.floor(Date.now() / 1000),
}: BuildSecurityIntelligenceParams): SecurityIntelligence {
  const evidence: SecurityIntelligence["evidence"] = [];

  const normalizedWallet = normalizeAddress(wallet);
  const normalizedSpender = normalizeAddress(spender);

  let approvalAgeDays: number | null = null;

  if (
    typeof approvalTimestamp === "number" &&
    Number.isFinite(approvalTimestamp) &&
    approvalTimestamp > 0
  ) {
    const ageSeconds = Math.max(
      0,
      now - approvalTimestamp
    );

    approvalAgeDays = Math.floor(
      ageSeconds / 86_400
    );

    evidence.push({
      type: "APPROVAL",
      description:
        approvalAgeDays === 0
          ? "The current approval was established within the last 24 hours."
          : `The current approval was established ${approvalAgeDays} days ago.`,
      timestamp: approvalTimestamp,
    });
  }

  const spenderInteractions = transactions
    .map((transaction) => {
      const from = normalizeAddress(transaction.from);
      const to = normalizeAddress(transaction.to);
      const timestamp = getTimestamp(transaction);

      return {
        transaction,
        from,
        to,
        timestamp,
      };
    })
    .filter((item) => {
      if (!item.timestamp) {
        return false;
      }

      const walletSentToSpender =
        item.from === normalizedWallet &&
        item.to === normalizedSpender;

      return walletSentToSpender;
    })
    .sort(
      (a, b) =>
        (b.timestamp ?? 0) - (a.timestamp ?? 0)
    );

  const spenderInteractionCount =
    spenderInteractions.length;

  const walletInteractedWithSpender =
    spenderInteractionCount > 0
      ? true
      : historyLimitReached
        ? null
        : false;

  let activityStatus: SecurityIntelligence["activityStatus"];

  if (spenderInteractionCount > 0) {
    activityStatus = "ACTIVE";
  } else if (historyLimitReached) {
    activityStatus = "UNKNOWN";
  } else {
    activityStatus = "NO_INTERACTION_FOUND";
  }

  const lastSpenderInteraction =
    spenderInteractions[0]?.timestamp ?? null;

  if (spenderInteractions.length > 0) {
    for (
      let index = 0;
      index <
      Math.min(spenderInteractions.length, 3);
      index++
    ) {
      const interaction =
        spenderInteractions[index];

      if (!interaction.timestamp) {
        continue;
      }

      const daysAgo = Math.floor(
        Math.max(
          0,
          now - interaction.timestamp
        ) / 86_400
      );

      evidence.push({
        type:
          daysAgo <= 30
            ? "RECENT_ACTIVITY"
            : "SPENDER_INTERACTION",

        description:
          daysAgo === 0
            ? "The wallet interacted with this spender today."
            : `The wallet interacted with this spender ${daysAgo} days ago.`,

        timestamp: interaction.timestamp,

        txHash:
          interaction.transaction.hash,
      });
    }
  }

  if (historyLimitReached) {
    evidence.push({
      type: "HISTORY_LIMIT",
      description:
        "Historical analysis reached the configured transaction history limit. Absence of an interaction is not proof that no interaction ever occurred.",
    });
  }

  return {
    approvalAgeDays,

    approvalAgeBand:
      getApprovalAgeBand(approvalAgeDays),

    walletInteractedWithSpender,

    spenderInteractionCount,

    lastSpenderInteraction,

    activityStatus,

    evidence,
  };
}