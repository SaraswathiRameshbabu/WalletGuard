"use client";
import type { SecurityIntelligence } from "@/lib/security-intelligence";
import type { Permit2Intelligence } from "@/lib/permit2-intelligence";
import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import {
  createPublicClient,
  createWalletClient,
  custom,
  encodeFunctionData,
  formatUnits,
  http,
  isAddress,
  parseAbi,
  type Address,
  type Hash,
} from "viem";
import { mainnet } from "viem/chains";


declare global {
  interface Window {
    ethereum?: {
      isMetaMask?: boolean;
      request: (args: {
        method: string;
        params?: unknown[];
      }) => Promise<unknown>;
      on?: (event: string, handler: (...args: unknown[]) => void) => void;
      removeListener?: (
        event: string,
        handler: (...args: unknown[]) => void
      ) => void;
    };
  }
}

type RiskLevel = "HIGH" | "REVIEW" | "LOW" | "NO_EXPOSURE";

type SpenderClassification =
  | "UNKNOWN"
  | "KNOWN_PROTOCOL"
  | "KNOWN_INFRASTRUCTURE";

type FindingStatus =
  | "ACTIVE"
  | "NO_EXPOSURE"
  | "REVOKED"
  | "VERIFYING"
  | "UNKNOWN";

type RiskVector = {
  permission?: string;
  assetExposure?: string;
  spenderRisk?: string;
  activityRisk?: string;
  contractRisk?: string;
  dataConfidence?: string;
};

type Finding = {
  token: string;
  tokenSymbol?: string;
  tokenDecimals?: number;

  spender: string;
  spenderLabel?: string;
  spenderClassification?: SpenderClassification;

  allowance?: string;
  allowanceFormatted?: string;

  walletBalance?: string;
  walletBalanceFormatted?: string;

  currentExposure?: string;
  currentExposureFormatted?: string;

  unlimited?: boolean;

  approvalTransactionHash?: string;
  approvalBlockNumber?: string | number;
  approvalTimestamp?: string | number;

  status?: FindingStatus;
  risk?: RiskLevel;

  riskVector?: RiskVector;
  securityIntelligence?: SecurityIntelligence;
  permit2Intelligence?: Permit2Intelligence;
  explanation?: string;
};

type ScanSummary = {
  totalActive?: number;
  high?: number;
  review?: number;
  low?: number;
  noExposure?: number;
};

type ScanInfo = {
  source?: string;
  liveStateVerified?: boolean;
  exposureFormula?: string;
  historicalTransactionLimit?: number;
  usdPricing?: boolean;
  note?: string;
};

type ApprovalsResponse = {
  schemaVersion?: number;
  address?: string;
  chainId?: number;
  summary?: ScanSummary;
  topFindings?: Finding[];
  findings?: Finding[];
  scanInfo?: ScanInfo;
  error?: string;
  message?: string;
};

type ActivityItem = {
  id: string;
  time: number;
  type: "SCAN" | "REVOKE" | "VERIFY" | "INFO" | "ERROR";
  title: string;
  description: string;
  hash?: string;
};

type ScanSnapshot = {
  timestamp: number;
  total: number;
  high: number;
  review: number;
  low: number;
  noExposure: number;
};


const API_ENDPOINT = "/api/approvals";

const ETHEREUM_CHAIN_ID = 1;
const ETHEREUM_CHAIN_HEX = "0x1";

const APPROVE_ABI = parseAbi([
  "function approve(address spender, uint256 amount) returns (bool)",
]);

const ZERO_UINT256 = (2n ** 256n - 1n).toString();

const PAGE_SIZE = 20;

const RISK_ORDER: Record<RiskLevel, number> = {
  HIGH: 4,
  REVIEW: 3,
  LOW: 2,
  NO_EXPOSURE: 1,
};


function shortenAddress(address?: string, chars = 6) {
  if (!address) return "—";

  if (address.length < chars * 2 + 5) {
    return address;
  }

  return `${address.slice(0, chars + 2)}…${address.slice(-chars)}`;
}

function shortenHash(hash?: string) {
  if (!hash) return "—";

  return `${hash.slice(0, 10)}…${hash.slice(-8)}`;
}

function displaySymbol(symbol?: string) {
  if (!symbol || !symbol.trim()) {
    return "Unknown";
  }

  return symbol.trim();
}

function formatNumber(value: number) {
  return new Intl.NumberFormat("en-US").format(value);
}

function safeNumber(value?: string | number) {
  if (typeof value === "number") return value;

  const parsed = Number(value);

  return Number.isFinite(parsed) ? parsed : 0;
}

function getRiskLabel(risk?: RiskLevel) {
  switch (risk) {
    case "HIGH":
      return "High exposure";

    case "REVIEW":
      return "Review";

    case "LOW":
      return "Low exposure";

    case "NO_EXPOSURE":
      return "No exposure";

    default:
      return "Unknown";
  }
}

function getRiskDescription(risk?: RiskLevel) {
  switch (risk) {
    case "HIGH":
      return "Live balance exposure with a high-risk permission context.";

    case "REVIEW":
      return "The permission is active and deserves additional review.";

    case "LOW":
      return "Active permission with currently limited exposure.";

    case "NO_EXPOSURE":
      return "The permission exists, but the wallet currently has no exposed balance.";

    default:
      return "The current risk state could not be classified.";
  }
}

function getClassificationLabel(
  classification?: SpenderClassification
) {
  switch (classification) {
    case "KNOWN_PROTOCOL":
      return "Recognized protocol";

    case "KNOWN_INFRASTRUCTURE":
      return "Recognized infrastructure";

    case "UNKNOWN":
      return "Unknown spender";

    default:
      return "Unclassified spender";
  }
}

function normalizeFindings(data: ApprovalsResponse): Finding[] {
  if (Array.isArray(data.topFindings)) {
    return data.topFindings;
  }

  if (Array.isArray(data.findings)) {
    return data.findings;
  }

  return [];
}

function getExposureNumber(finding: Finding) {
  const raw =
    finding.currentExposureFormatted ??
    finding.currentExposure ??
    "0";

  const parsed = Number(raw);

  return Number.isFinite(parsed) ? parsed : 0;
}

function getRisk(finding: Finding): RiskLevel {
  if (
    finding.risk === "HIGH" ||
    finding.risk === "REVIEW" ||
    finding.risk === "LOW" ||
    finding.risk === "NO_EXPOSURE"
  ) {
    return finding.risk;
  }

  return "REVIEW";
}

function isFindingActive(finding: Finding) {
  return (
    finding.status !== "REVOKED" &&
    finding.status !== "VERIFYING"
  );
}

function createActivity(
  type: ActivityItem["type"],
  title: string,
  description: string,
  hash?: string
): ActivityItem {
  return {
    id: `${Date.now()}-${Math.random()}`,
    time: Date.now(),
    type,
    title,
    description,
    hash,
  };
}

function formatTime(timestamp: number) {
  return new Intl.DateTimeFormat("en-IN", {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  }).format(timestamp);
}


function IconShield({ size = 20 }: { size?: number }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      aria-hidden="true"
    >
      <path
        d="M12 3L20 6V11.5C20 16.5 16.8 20.1 12 21C7.2 20.1 4 16.5 4 11.5V6L12 3Z"
        stroke="currentColor"
        strokeWidth="1.8"
        strokeLinejoin="round"
      />
      <path
        d="M8.5 12L10.8 14.3L15.8 9.3"
        stroke="currentColor"
        strokeWidth="1.8"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

function IconWallet({ size = 20 }: { size?: number }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      aria-hidden="true"
    >
      <path
        d="M4 7.5C4 6.12 5.12 5 6.5 5H19C20.1 5 21 5.9 21 7V18C21 19.1 20.1 20 19 20H6C4.9 20 4 19.1 4 18V7.5Z"
        stroke="currentColor"
        strokeWidth="1.8"
      />
      <path
        d="M4 8H18.5C19.88 8 21 9.12 21 10.5V13H17C15.9 13 15 12.1 15 11C15 9.9 15.9 9 17 9H21"
        stroke="currentColor"
        strokeWidth="1.8"
      />
      <circle cx="17.2" cy="11" r="0.8" fill="currentColor" />
    </svg>
  );
}

function IconSearch({ size = 18 }: { size?: number }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      aria-hidden="true"
    >
      <circle
        cx="10.8"
        cy="10.8"
        r="6.3"
        stroke="currentColor"
        strokeWidth="1.8"
      />
      <path
        d="M16 16L21 21"
        stroke="currentColor"
        strokeWidth="1.8"
        strokeLinecap="round"
      />
    </svg>
  );
}

function IconRefresh({
  size = 18,
  spinning = false,
}: {
  size?: number;
  spinning?: boolean;
}) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      className={spinning ? "animate-spin" : ""}
      aria-hidden="true"
    >
      <path
        d="M20 11A8 8 0 0 0 6.2 5.2L4 7.5"
        stroke="currentColor"
        strokeWidth="1.8"
        strokeLinecap="round"
      />
      <path
        d="M4 4.5V7.5H7"
        stroke="currentColor"
        strokeWidth="1.8"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      <path
        d="M4 13A8 8 0 0 0 17.8 18.8L20 16.5"
        stroke="currentColor"
        strokeWidth="1.8"
        strokeLinecap="round"
      />
      <path
        d="M20 19.5V16.5H17"
        stroke="currentColor"
        strokeWidth="1.8"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

function IconCheck({ size = 18 }: { size?: number }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      aria-hidden="true"
    >
      <path
        d="M5 12.5L9.2 17L19 7"
        stroke="currentColor"
        strokeWidth="2"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

function IconAlert({ size = 18 }: { size?: number }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      aria-hidden="true"
    >
      <path
        d="M12 4L21 20H3L12 4Z"
        stroke="currentColor"
        strokeWidth="1.8"
        strokeLinejoin="round"
      />
      <path
        d="M12 9V13"
        stroke="currentColor"
        strokeWidth="1.8"
        strokeLinecap="round"
      />
      <circle cx="12" cy="16.5" r="0.9" fill="currentColor" />
    </svg>
  );
}

function IconLock({ size = 18 }: { size?: number }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      aria-hidden="true"
    >
      <rect
        x="5"
        y="10"
        width="14"
        height="10"
        rx="2"
        stroke="currentColor"
        strokeWidth="1.8"
      />
      <path
        d="M8 10V7.5C8 5.29 9.79 3.5 12 3.5C14.21 3.5 16 5.29 16 7.5V10"
        stroke="currentColor"
        strokeWidth="1.8"
      />
    </svg>
  );
}

function IconExternal({ size = 15 }: { size?: number }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      aria-hidden="true"
    >
      <path
        d="M14 5H19V10"
        stroke="currentColor"
        strokeWidth="1.8"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      <path
        d="M19 5L12 12"
        stroke="currentColor"
        strokeWidth="1.8"
        strokeLinecap="round"
      />
      <path
        d="M18 13V18C18 19.1 17.1 20 16 20H6C4.9 20 4 19.1 4 18V8C4 6.9 4.9 6 6 6H11"
        stroke="currentColor"
        strokeWidth="1.8"
        strokeLinecap="round"
      />
    </svg>
  );
}

function IconX({ size = 20 }: { size?: number }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      aria-hidden="true"
    >
      <path
        d="M6 6L18 18"
        stroke="currentColor"
        strokeWidth="1.8"
        strokeLinecap="round"
      />
      <path
        d="M18 6L6 18"
        stroke="currentColor"
        strokeWidth="1.8"
        strokeLinecap="round"
      />
    </svg>
  );
}

function IconActivity({ size = 18 }: { size?: number }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      aria-hidden="true"
    >
      <path
        d="M3 12H7L9.5 5L14 19L16.5 12H21"
        stroke="currentColor"
        strokeWidth="1.8"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

function IconEye({ size = 17 }: { size?: number }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      aria-hidden="true"
    >
      <path
        d="M2.5 12S6 5.5 12 5.5 21.5 12 21.5 12 18 18.5 12 18.5 2.5 12 2.5 12Z"
        stroke="currentColor"
        strokeWidth="1.7"
      />
      <circle
        cx="12"
        cy="12"
        r="2.8"
        stroke="currentColor"
        strokeWidth="1.7"
      />
    </svg>
  );
}

export default function Page() {
  const [walletAddress, setWalletAddress] = useState<Address | null>(null);
  const [chainId, setChainId] = useState<number | null>(null);

  const [findings, setFindings] = useState<Finding[]>([]);
  const [summary, setSummary] = useState<ScanSummary>({
    totalActive: 0,
    high: 0,
    review: 0,
    low: 0,
    noExposure: 0,
  });

  const [scanInfo, setScanInfo] = useState<ScanInfo | null>(null);

  const [connecting, setConnecting] = useState(false);
  const [scanning, setScanning] = useState(false);

  const [manualWallet, setManualWallet] = useState("");
  const [manualWalletScanning, setManualWalletScanning] = useState(false);
  const [readOnlyWallet, setReadOnlyWallet] = useState(false);

  const [scanError, setScanError] = useState("");
  const [successMessage, setSuccessMessage] = useState("");

  const [selectedFinding, setSelectedFinding] =
    useState<Finding | null>(null);

  const [revokeTarget, setRevokeTarget] =
    useState<Finding | null>(null);

  const [revoking, setRevoking] = useState(false);

  const [searchQuery, setSearchQuery] = useState("");

  const [riskFilter, setRiskFilter] =
    useState<"ALL" | RiskLevel>("ALL");

  const [classificationFilter, setClassificationFilter] =
    useState<"ALL" | SpenderClassification>("ALL");

  const [sortMode, setSortMode] = useState<
    "RISK" | "EXPOSURE" | "TOKEN"
  >("RISK");

  const [page, setPage] = useState(1);

  const [monitorEnabled, setMonitorEnabled] = useState(false);

  const [lastScanAt, setLastScanAt] = useState<number | null>(
    null
  );

  const [lastSnapshot, setLastSnapshot] =
    useState<ScanSnapshot | null>(null);

  const [activity, setActivity] = useState<ActivityItem[]>([]);

  const scanLock = useRef(false);
  const mountedRef = useRef(false);

  const provider = useMemo(() => {
    if (typeof window === "undefined") {
      return null;
    }

    if (!window.ethereum) {
      return null;
    }

    return window.ethereum;
  }, [walletAddress]);

  const walletClient = useMemo(() => {
    if (!provider) {
      return null;
    }

    return createWalletClient({
      chain: mainnet,
      transport: custom(provider),
    });
  }, [provider]);

  const publicClient = useMemo(() => {
    if (!provider) {
      return null;
    }

    return createPublicClient({
      chain: mainnet,
      transport: custom(provider),
    });
  }, [provider]);


  const addActivity = useCallback(
    (
      type: ActivityItem["type"],
      title: string,
      description: string,
      hash?: string
    ) => {
      setActivity((previous) => [
        createActivity(type, title, description, hash),
        ...previous,
      ].slice(0, 12));
    },
    []
  );


  const connectWallet = useCallback(async () => {
    if (!window.ethereum) {
      setScanError(
        "MetaMask was not detected. Install MetaMask and refresh the page."
      );
      return;
    }

    if (connecting) {
      return;
    }

    setConnecting(true);
    setScanError("");
    setSuccessMessage("");

    try {
      const accounts = (await window.ethereum.request({
        method: "eth_requestAccounts",
      })) as string[];

      if (!accounts?.length || !isAddress(accounts[0])) {
        throw new Error("No valid wallet address was returned.");
      }

      const address = accounts[0] as Address;

      const rawChainId = (await window.ethereum.request({
        method: "eth_chainId",
      })) as string;

      const numericChainId = Number.parseInt(
        rawChainId,
        16
      );

      setWalletAddress(address);
      setChainId(numericChainId);
      setReadOnlyWallet(false);

      if (numericChainId !== ETHEREUM_CHAIN_ID) {
        setScanError(
          "Wallet connected, but the selected network is not Ethereum Mainnet."
        );
        addActivity(
          "ERROR",
          "Wrong network",
          "Switch MetaMask to Ethereum Mainnet before scanning."
        );
      } else {
        setSuccessMessage("Wallet connected on Ethereum Mainnet.");

        addActivity(
          "INFO",
          "Wallet connected",
          `Connected ${shortenAddress(address)} on Ethereum Mainnet.`
        );
      }
    } catch (error) {
      const message =
        error instanceof Error
          ? error.message
          : "Wallet connection was cancelled.";

      if (
        message.toLowerCase().includes("already pending")
      ) {
        setScanError(
          "A MetaMask connection request is already pending. Complete it in MetaMask."
        );
      } else {
        setScanError(message);
      }
    } finally {
      setConnecting(false);
    }
  }, [addActivity, connecting]);


  const switchToEthereum = useCallback(async () => {
    if (!window.ethereum) {
      setScanError("MetaMask is not available.");
      return;
    }

    try {
      await window.ethereum.request({
        method: "wallet_switchEthereumChain",
        params: [{ chainId: ETHEREUM_CHAIN_HEX }],
      });

      setChainId(ETHEREUM_CHAIN_ID);
      setScanError("");
      setSuccessMessage(
        "Ethereum Mainnet selected. You can scan now."
      );

      addActivity(
        "INFO",
        "Network changed",
        "Wallet switched to Ethereum Mainnet."
      );
    } catch (error) {
      const message =
        error instanceof Error
          ? error.message
          : "Could not switch network.";

      setScanError(message);
    }
  }, [addActivity]);


  const scanManualWallet = useCallback(async () => {
    const address = manualWallet.trim();

    if (!isAddress(address)) {
      setScanError("Enter a valid Ethereum wallet address.");
      return;
    }

    if (manualWalletScanning || scanLock.current) {
      return;
    }

    scanLock.current = true;
    setManualWalletScanning(true);
    setScanning(true);
    setScanError("");
    setSuccessMessage("");

    try {
      const normalizedAddress = address as Address;

      const response = await fetch(
        `${API_ENDPOINT}?address=${encodeURIComponent(
          normalizedAddress
        )}`,
        {
          method: "GET",
          cache: "no-store",
          headers: {
            Accept: "application/json",
          },
        }
      );

      const data =
        (await response.json()) as ApprovalsResponse;

      if (!response.ok) {
        throw new Error(
          data.error ||
            data.message ||
            `Scan failed with HTTP ${response.status}.`
        );
      }

      if (data.error) {
        throw new Error(data.error);
      }

      const nextFindings = normalizeFindings(data);

      const nextSummary: ScanSummary = {
        totalActive:
          data.summary?.totalActive ??
          nextFindings.filter(isFindingActive).length,

        high:
          data.summary?.high ??
          nextFindings.filter(
            (item) => getRisk(item) === "HIGH"
          ).length,

        review:
          data.summary?.review ??
          nextFindings.filter(
            (item) => getRisk(item) === "REVIEW"
          ).length,

        low:
          data.summary?.low ??
          nextFindings.filter(
            (item) => getRisk(item) === "LOW"
          ).length,

        noExposure:
          data.summary?.noExposure ??
          nextFindings.filter(
            (item) => getRisk(item) === "NO_EXPOSURE"
          ).length,
      };

      setWalletAddress(normalizedAddress);
      setChainId(ETHEREUM_CHAIN_ID);
      setReadOnlyWallet(true);
      setFindings(nextFindings);
      setSummary(nextSummary);
      setScanInfo(data.scanInfo ?? null);
      setLastScanAt(Date.now());
      setPage(1);

      const snapshot: ScanSnapshot = {
        timestamp: Date.now(),
        total: nextSummary.totalActive ?? 0,
        high: nextSummary.high ?? 0,
        review: nextSummary.review ?? 0,
        low: nextSummary.low ?? 0,
        noExposure: nextSummary.noExposure ?? 0,
      };

      setLastSnapshot(snapshot);

      setSuccessMessage(
        `Read-only scan complete. ${formatNumber(
          nextSummary.totalActive ?? 0
        )} active approvals analyzed.`
      );

      addActivity(
        "SCAN",
        "Manual wallet scan completed",
        `${formatNumber(
          nextSummary.totalActive ?? 0
        )} active approvals analyzed for ${shortenAddress(
          normalizedAddress
        )}.`
      );
    } catch (error) {
      const message =
        error instanceof Error
          ? error.message
          : "Wallet scan failed.";

      setScanError(message);

      addActivity(
        "ERROR",
        "Manual wallet scan failed",
        message
      );
    } finally {
      scanLock.current = false;
      setManualWalletScanning(false);
      setScanning(false);
    }
  }, [addActivity, manualWallet, manualWalletScanning]);


  const scanWallet = useCallback(
    async (silent = false) => {
      if (!walletAddress) {
        if (!silent) {
          setScanError("Connect MetaMask before scanning.");
        }
        return;
      }

      if (chainId !== ETHEREUM_CHAIN_ID) {
        if (!silent) {
          setScanError(
            "Switch MetaMask to Ethereum Mainnet before scanning."
          );
        }
        return;
      }

      if (scanLock.current) {
        return;
      }

      scanLock.current = true;
      setScanning(true);

      if (!silent) {
        setScanError("");
        setSuccessMessage("");
      }

      try {
        const response = await fetch(
          `${API_ENDPOINT}?address=${encodeURIComponent(
            walletAddress
          )}`,
          {
            method: "GET",
            cache: "no-store",
            headers: {
              Accept: "application/json",
            },
          }
        );

        const data =
          (await response.json()) as ApprovalsResponse;

        if (!response.ok) {
          throw new Error(
            data.error ||
              data.message ||
              `Scan failed with HTTP ${response.status}.`
          );
        }

        if (data.error) {
          throw new Error(data.error);
        }

        const nextFindings = normalizeFindings(data);

        const nextSummary: ScanSummary = {
          totalActive:
            data.summary?.totalActive ??
            nextFindings.filter(isFindingActive).length,

          high:
            data.summary?.high ??
            nextFindings.filter(
              (item) => getRisk(item) === "HIGH"
            ).length,

          review:
            data.summary?.review ??
            nextFindings.filter(
              (item) => getRisk(item) === "REVIEW"
            ).length,

          low:
            data.summary?.low ??
            nextFindings.filter(
              (item) => getRisk(item) === "LOW"
            ).length,

          noExposure:
            data.summary?.noExposure ??
            nextFindings.filter(
              (item) => getRisk(item) === "NO_EXPOSURE"
            ).length,
        };

        setFindings(nextFindings);
        setSummary(nextSummary);
        setScanInfo(data.scanInfo ?? null);
        setLastScanAt(Date.now());

        setPage(1);

        const snapshot: ScanSnapshot = {
          timestamp: Date.now(),
          total: nextSummary.totalActive ?? 0,
          high: nextSummary.high ?? 0,
          review: nextSummary.review ?? 0,
          low: nextSummary.low ?? 0,
          noExposure: nextSummary.noExposure ?? 0,
        };

        setLastSnapshot(snapshot);

        if (!silent) {
          setSuccessMessage(
            `Scan complete. ${formatNumber(
              nextSummary.totalActive ?? 0
            )} active approvals analyzed.`
          );

          addActivity(
            "SCAN",
            "Wallet scan completed",
            `${formatNumber(
              nextSummary.totalActive ?? 0
            )} active approvals analyzed with live allowance and balance verification.`
          );
        } else {
          addActivity(
            "SCAN",
            "Monitor scan completed",
            `${formatNumber(
              nextSummary.totalActive ?? 0
            )} active approvals currently detected.`
          );
        }
      } catch (error) {
        const message =
          error instanceof Error
            ? error.message
            : "Wallet scan failed.";

        setScanError(message);

        addActivity(
          "ERROR",
          silent ? "Monitor scan failed" : "Wallet scan failed",
          message
        );
      } finally {
        scanLock.current = false;
        setScanning(false);
      }
    },
    [addActivity, chainId, walletAddress]
  );


  useEffect(() => {
    if (!mountedRef.current) {
      mountedRef.current = true;
      return;
    }

    if (!monitorEnabled || !walletAddress) {
      return;
    }

    const timer = window.setInterval(() => {
      void scanWallet(true);
    }, 60_000);

    return () => {
      window.clearInterval(timer);
    };
  }, [monitorEnabled, scanWallet, walletAddress]);


  useEffect(() => {
    if (!window.ethereum?.on) {
      return;
    }

    const handleAccountsChanged = (...args: unknown[]) => {
      const accounts = args[0] as string[] | undefined;

      if (!accounts?.length || !isAddress(accounts[0])) {
        setWalletAddress(null);
        setFindings([]);
        setSummary({
          totalActive: 0,
          high: 0,
          review: 0,
          low: 0,
          noExposure: 0,
        });

        setSuccessMessage("");
        setScanError("Wallet disconnected.");
        return;
      }

      const address = accounts[0] as Address;

      setWalletAddress(address);
      setReadOnlyWallet(false);

      addActivity(
        "INFO",
        "Wallet changed",
        `Active wallet is now ${shortenAddress(address)}.`
      );
    };

    const handleChainChanged = (...args: unknown[]) => {
      const rawChainId = args[0] as string;

      const numericChainId = Number.parseInt(
        rawChainId,
        16
      );

      setChainId(numericChainId);

      if (numericChainId !== ETHEREUM_CHAIN_ID) {
        setScanError(
          "Network changed. Switch back to Ethereum Mainnet."
        );
      } else {
        setScanError("");
        setSuccessMessage(
          "Ethereum Mainnet detected."
        );
      }
    };

    window.ethereum.on(
      "accountsChanged",
      handleAccountsChanged
    );

    window.ethereum.on(
      "chainChanged",
      handleChainChanged
    );

    return () => {
      window.ethereum?.removeListener?.(
        "accountsChanged",
        handleAccountsChanged
      );

      window.ethereum?.removeListener?.(
        "chainChanged",
        handleChainChanged
      );
    };
  }, [addActivity]);


  useEffect(() => {
    let cancelled = false;

    async function restoreWallet() {
      if (!window.ethereum) {
        return;
      }

      try {
        const accounts = (await window.ethereum.request({
          method: "eth_accounts",
        })) as string[];

        if (cancelled) {
          return;
        }

        if (
          accounts?.length &&
          isAddress(accounts[0])
        ) {
          setWalletAddress(accounts[0] as Address);
        }

        const rawChainId =
          (await window.ethereum.request({
            method: "eth_chainId",
          })) as string;

        if (!cancelled) {
          setChainId(
            Number.parseInt(rawChainId, 16)
          );
        }
      } catch {
        // Initial wallet restoration is intentionally silent.
      }
    }

    void restoreWallet();

    return () => {
      cancelled = true;
    };
  }, []);


  const filteredFindings = useMemo(() => {
    const query = searchQuery.trim().toLowerCase();

    const filtered = findings.filter((finding) => {
      const risk = getRisk(finding);

      if (
        riskFilter !== "ALL" &&
        risk !== riskFilter
      ) {
        return false;
      }

      if (
        classificationFilter !== "ALL" &&
        finding.spenderClassification !==
          classificationFilter
      ) {
        return false;
      }

      if (!query) {
        return true;
      }

      const searchable = [
        finding.token,
        finding.tokenSymbol,
        finding.spender,
        finding.spenderLabel,
        finding.spenderClassification,
        finding.approvalTransactionHash,
      ]
        .filter(Boolean)
        .join(" ")
        .toLowerCase();

      return searchable.includes(query);
    });

    return [...filtered].sort((a, b) => {
      if (sortMode === "TOKEN") {
        return displaySymbol(a.tokenSymbol).localeCompare(
          displaySymbol(b.tokenSymbol)
        );
      }

      if (sortMode === "EXPOSURE") {
        return (
          getExposureNumber(b) -
          getExposureNumber(a)
        );
      }

      return (
        RISK_ORDER[getRisk(b)] -
        RISK_ORDER[getRisk(a)]
      );
    });
  }, [
    classificationFilter,
    findings,
    riskFilter,
    searchQuery,
    sortMode,
  ]);

  const totalPages = Math.max(
    1,
    Math.ceil(
      filteredFindings.length / PAGE_SIZE
    )
  );

  const visibleFindings = useMemo(() => {
    const start = (page - 1) * PAGE_SIZE;

    return filteredFindings.slice(
      start,
      start + PAGE_SIZE
    );
  }, [filteredFindings, page]);

  useEffect(() => {
    if (page > totalPages) {
      setPage(totalPages);
    }
  }, [page, totalPages]);


  const revokeApproval = useCallback(
    async (finding: Finding) => {
      if (!walletAddress) {
        setScanError(
          "Connect the wallet before revoking."
        );
        return;
      }

      if (readOnlyWallet) {
        setScanError(
          "This wallet was scanned in read-only mode. Connect the same wallet in MetaMask before revoking."
        );
        return;
      }

      if (chainId !== ETHEREUM_CHAIN_ID) {
        setScanError(
          "Switch MetaMask to Ethereum Mainnet before revoking."
        );
        return;
      }

      if (!walletClient || !publicClient) {
        setScanError(
          "Wallet provider is not available."
        );
        return;
      }

      if (!isAddress(finding.token)) {
        setScanError(
          "The token address returned by the scanner is invalid."
        );
        return;
      }

      if (!isAddress(finding.spender)) {
        setScanError(
          "The spender address returned by the scanner is invalid."
        );
        return;
      }

      setRevoking(true);
      setScanError("");
      setSuccessMessage("");

      setFindings((previous) =>
        previous.map((item) =>
          item.token.toLowerCase() ===
            finding.token.toLowerCase() &&
          item.spender.toLowerCase() ===
            finding.spender.toLowerCase()
            ? {
                ...item,
                status: "VERIFYING",
              }
            : item
        )
      );

      addActivity(
        "INFO",
        "Revocation requested",
        `Preparing to revoke ${displaySymbol(
          finding.tokenSymbol
        )} permission for ${shortenAddress(
          finding.spender
        )}.`
      );

      try {
        const data = encodeFunctionData({
          abi: APPROVE_ABI,
          functionName: "approve",
          args: [
            finding.spender as Address,
            0n,
          ],
        });

        const hash = await walletClient.sendTransaction({
          account: walletAddress,
          to: finding.token as Address,
          data,
          chain: mainnet,
        });

        addActivity(
          "REVOKE",
          "Revocation submitted",
          `Approval reset transaction submitted for ${displaySymbol(
            finding.tokenSymbol
          )}.`,
          hash
        );

        setSuccessMessage(
          `Revocation submitted: ${shortenHash(hash)}`
        );

        setRevokeTarget(null);

        await publicClient.waitForTransactionReceipt({
          hash,
        });

        addActivity(
          "VERIFY",
          "Transaction confirmed",
          `Ethereum confirmed the approval reset for ${displaySymbol(
            finding.tokenSymbol
          )}.`,
          hash
        );

        
        const verifyUrl =
          `${API_ENDPOINT}?address=${encodeURIComponent(
            walletAddress
          )}` +
          `&verifyToken=${encodeURIComponent(
            finding.token
          )}` +
          `&verifySpender=${encodeURIComponent(
            finding.spender
          )}`;

        const verifyResponse = await fetch(
          verifyUrl,
          {
            method: "GET",
            cache: "no-store",
            headers: {
              Accept: "application/json",
            },
          }
        );

        const verifyData =
          (await verifyResponse.json()) as ApprovalsResponse;

        if (!verifyResponse.ok) {
          throw new Error(
            verifyData.error ||
              "Transaction confirmed, but post-revoke verification failed."
          );
        }

        const verifiedFindings =
          normalizeFindings(verifyData);

        const stillActive = verifiedFindings.some(
          (item) =>
            item.token.toLowerCase() ===
              finding.token.toLowerCase() &&
            item.spender.toLowerCase() ===
              finding.spender.toLowerCase() &&
            item.status !== "REVOKED"
        );

        if (stillActive) {
          setSuccessMessage(
            "Transaction confirmed, but the approval still appears active. Re-scan to verify the latest state."
          );

          addActivity(
            "VERIFY",
            "Approval still detected",
            "The transaction was confirmed, but the latest verification still returned an active permission."
          );
        } else {
          setFindings((previous) =>
            previous.map((item) =>
              item.token.toLowerCase() ===
                finding.token.toLowerCase() &&
              item.spender.toLowerCase() ===
                finding.spender.toLowerCase()
                ? {
                    ...item,
                    allowance: "0",
                    allowanceFormatted: "0",
                    currentExposure: "0",
                    currentExposureFormatted: "0",
                    status: "REVOKED",
                    risk: "NO_EXPOSURE",
                  }
                : item
            )
          );

          setSuccessMessage(
            `${displaySymbol(
              finding.tokenSymbol
            )} approval successfully revoked and verified.`
          );

          addActivity(
            "VERIFY",
            "Approval revoked",
            `${displaySymbol(
              finding.tokenSymbol
            )} permission is no longer active for this spender.`,
            hash
          );
        }
      } catch (error) {
        const message =
          error instanceof Error
            ? error.message
            : "Revocation failed.";

        setFindings((previous) =>
          previous.map((item) =>
            item.token.toLowerCase() ===
              finding.token.toLowerCase() &&
            item.spender.toLowerCase() ===
              finding.spender.toLowerCase()
              ? {
                  ...item,
                  status: "ACTIVE",
                }
              : item
          )
        );

        if (
          message.toLowerCase().includes("user rejected") ||
          message.toLowerCase().includes("denied")
        ) {
          setScanError(
            "The MetaMask signature was rejected. No revocation transaction was completed."
          );
        } else {
          setScanError(message);
        }

        addActivity(
          "ERROR",
          "Revocation failed",
          message
        );
      } finally {
        setRevoking(false);
      }
    },
    [
      addActivity,
      chainId,
      publicClient,
      readOnlyWallet,
      walletAddress,
      walletClient,
    ]
  );


  const activeExposureCount = useMemo(
    () =>
      findings.filter(
        (item) =>
          getExposureNumber(item) > 0 &&
          item.status !== "REVOKED"
      ).length,
    [findings]
  );

  const monitorDelta = useMemo(() => {
    if (!lastSnapshot) {
      return null;
    }

    return {
      high:
        (summary.high ?? 0) -
        lastSnapshot.high,

      review:
        (summary.review ?? 0) -
        lastSnapshot.review,

      total:
        (summary.totalActive ?? 0) -
        lastSnapshot.total,
    };
  }, [lastSnapshot, summary]);


  const walletReady =
    Boolean(walletAddress) &&
    chainId === ETHEREUM_CHAIN_ID;


  return (
    <main className="min-h-screen bg-[#070b12] text-white">
      <div className="pointer-events-none fixed inset-0 overflow-hidden">
        <div className="absolute left-[8%] top-[-15%] h-[420px] w-[420px] rounded-full bg-cyan-500/10 blur-[120px]" />
        <div className="absolute right-[4%] top-[25%] h-[360px] w-[360px] rounded-full bg-violet-500/10 blur-[120px]" />
      </div>

      <div className="relative mx-auto max-w-[1500px] px-4 py-5 sm:px-6 lg:px-8">
        {/* =================================================
            HEADER
        ================================================= */}

        <header className="mb-6 flex flex-col gap-4 border-b border-white/10 pb-5 lg:flex-row lg:items-center lg:justify-between">
          <div className="flex items-center gap-3">
            <div className="flex h-11 w-11 items-center justify-center rounded-2xl border border-cyan-400/20 bg-cyan-400/10 text-cyan-300">
              <IconShield size={24} />
            </div>

            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-xl font-bold tracking-tight">
                  WalletGuard
                </h1>
              </div>

              <p className="text-xs text-slate-400">
                Active approval security & continuous protection
              </p>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <div className="flex items-center gap-2 rounded-xl border border-white/10 bg-white/[0.03] px-3 py-2 text-xs">
              <span
                className={`h-2 w-2 rounded-full ${
                  walletReady
                    ? "bg-emerald-400 shadow-[0_0_12px_rgba(52,211,153,.8)]"
                    : "bg-slate-500"
                }`}
              />

              <span className="text-slate-300">
                {walletReady
                  ? "Ethereum Mainnet"
                  : "Wallet not ready"}
              </span>
            </div>

            {walletAddress ? (
              <button
                type="button"
                onClick={() => {
                  void scanWallet(false);
                }}
                disabled={
                  scanning ||
                  chainId !== ETHEREUM_CHAIN_ID
                }
                className="inline-flex items-center gap-2 rounded-xl border border-cyan-400/20 bg-cyan-400/10 px-4 py-2 text-sm font-semibold text-cyan-200 transition hover:bg-cyan-400/15 disabled:cursor-not-allowed disabled:opacity-50"
              >
                <IconRefresh
                  size={16}
                  spinning={scanning}
                />
                {scanning
                  ? "Scanning..."
                  : "Scan Wallet"}
              </button>
            ) : (
              <button
                type="button"
                onClick={() => {
                  void connectWallet();
                }}
                disabled={connecting}
                className="inline-flex items-center gap-2 rounded-xl bg-white px-4 py-2 text-sm font-semibold text-slate-950 transition hover:bg-slate-200 disabled:cursor-not-allowed disabled:opacity-60"
              >
                <IconWallet size={17} />
                {connecting
                  ? "Connecting..."
                  : "Connect MetaMask"}
              </button>
            )}
          </div>
        </header>

        {/* =================================================
            MANUAL WALLET ENTRY
            Added only: existing UI remains unchanged.
        ================================================= */}

        <section className="mb-6 rounded-2xl border border-white/10 bg-white/[0.025] p-4 sm:p-5">
          <div className="flex flex-col gap-3 lg:flex-row lg:items-end">
            <div className="flex-1">
              <div className="mb-1 text-[10px] font-semibold uppercase tracking-[0.16em] text-slate-500">
                Check any wallet
              </div>

              <p className="mb-2 text-xs text-slate-500">
                Enter a public Ethereum address to scan without connecting MetaMask.
              </p>

              <input
                value={manualWallet}
                onChange={(event) => {
                  setManualWallet(event.target.value);
                  setScanError("");
                }}
                onKeyDown={(event) => {
                  if (event.key === "Enter") {
                    void scanManualWallet();
                  }
                }}
                placeholder="0x..."
                aria-label="Ethereum wallet address"
                className="h-11 w-full rounded-xl border border-white/10 bg-black/20 px-4 font-mono text-xs text-slate-200 outline-none transition placeholder:text-slate-700 focus:border-cyan-400/30"
              />
            </div>

            <button
              type="button"
              onClick={() => {
                void scanManualWallet();
              }}
              disabled={
                manualWalletScanning ||
                scanning ||
                !manualWallet.trim()
              }
              className="inline-flex h-11 items-center justify-center gap-2 rounded-xl border border-cyan-400/20 bg-cyan-400/10 px-5 text-sm font-semibold text-cyan-200 transition hover:bg-cyan-400/15 disabled:cursor-not-allowed disabled:opacity-50 lg:w-auto"
            >
              <IconSearch size={16} />
              {manualWalletScanning
                ? "Checking..."
                : "Check Wallet"}
            </button>
          </div>

          {readOnlyWallet && walletAddress && (
            <div className="mt-3 flex flex-wrap items-center gap-2 text-[11px] text-slate-500">
              <span className="rounded-full border border-violet-400/20 bg-violet-400/10 px-2.5 py-1 text-violet-300">
                Read-only scan
              </span>

              <span>
                {shortenAddress(walletAddress, 8)}
              </span>

              <span className="text-slate-700">
                •
              </span>

              <span>
                Connect this wallet in MetaMask to revoke.
              </span>
            </div>
          )}
        </section>

        {/* =================================================
            HERO
        ================================================= */}

        <section className="mb-6 grid gap-5 lg:grid-cols-[1.6fr_.9fr]">
          <div className="overflow-hidden rounded-3xl border border-white/10 bg-gradient-to-br from-white/[0.07] to-white/[0.025] p-6 shadow-2xl shadow-black/20 sm:p-8">
            <div className="mb-5 inline-flex items-center gap-2 rounded-full border border-cyan-400/20 bg-cyan-400/10 px-3 py-1.5 text-xs font-medium text-cyan-200">
              <span className="h-1.5 w-1.5 rounded-full bg-cyan-300" />
              Detect → Verify → Explain → Revoke → Monitor
            </div>

            <h2 className="max-w-3xl text-3xl font-bold leading-tight tracking-tight sm:text-4xl">
              Your wallet should know{" "}
              <span className="text-cyan-300">
                who can spend its tokens.
              </span>
            </h2>

            <p className="mt-4 max-w-2xl text-sm leading-6 text-slate-400 sm:text-base">
              WalletGuard discovers live ERC-20 permissions,
              verifies current allowance and wallet balance
              on-chain, explains the resulting exposure, and
              lets you revoke permissions directly through
              MetaMask.
            </p>

            <div className="mt-6 flex flex-wrap gap-3">
              {walletAddress ? (
                <div className="flex items-center gap-3 rounded-2xl border border-white/10 bg-black/20 px-4 py-3">
                  <IconWallet size={18} />

                  <div>
                    <p className="text-[10px] uppercase tracking-wider text-slate-500">
                      Connected wallet
                    </p>

                    <p className="font-mono text-sm text-slate-200">
                      {shortenAddress(
                        walletAddress,
                        8
                      )}
                    </p>
                  </div>
                </div>
              ) : (
                <button
                  type="button"
                  onClick={() => {
                    void connectWallet();
                  }}
                  disabled={connecting}
                  className="rounded-2xl bg-cyan-400 px-5 py-3 text-sm font-bold text-slate-950 transition hover:bg-cyan-300 disabled:opacity-60"
                >
                  {connecting
                    ? "Waiting for MetaMask..."
                    : "Connect & Protect Wallet"}
                </button>
              )}

              <div className="flex items-center gap-2 rounded-2xl border border-white/10 bg-white/[0.025] px-4 py-3 text-xs text-slate-400">
                <IconLock size={16} />
                Non-custodial
              </div>
            </div>
          </div>

          {/* Protection loop */}
          <div className="rounded-3xl border border-white/10 bg-white/[0.035] p-6">
            <p className="text-xs font-semibold uppercase tracking-[0.2em] text-slate-500">
              Protection loop
            </p>

            <div className="mt-5 space-y-3">
              {[
                [
                  "01",
                  "Detect",
                  "Find active ERC-20 approvals.",
                ],
                [
                  "02",
                  "Verify",
                  "Read allowance + balance live.",
                ],
                [
                  "03",
                  "Explain",
                  "Show the actual exposure.",
                ],
                [
                  "04",
                  "Resolve",
                  "Revoke directly with MetaMask.",
                ],
                [
                  "05",
                  "Monitor",
                  "Re-check when wallet state changes.",
                ],
              ].map(([number, title, text]) => (
                <div
                  key={number}
                  className="flex items-center gap-3 rounded-2xl border border-white/5 bg-black/15 p-3"
                >
                  <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-xl bg-white/5 font-mono text-[10px] text-slate-500">
                    {number}
                  </span>

                  <div>
                    <p className="text-sm font-semibold text-slate-200">
                      {title}
                    </p>

                    <p className="text-xs text-slate-500">
                      {text}
                    </p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* =================================================
            ALERTS
        ================================================= */}

        {scanError && (
          <div className="mb-5 flex flex-col gap-3 rounded-2xl border border-red-400/20 bg-red-400/5 p-4 sm:flex-row sm:items-center sm:justify-between">
            <div className="flex items-start gap-3">
              <div className="mt-0.5 text-red-300">
                <IconAlert />
              </div>

              <div>
                <p className="text-sm font-semibold text-red-200">
                  Action needed
                </p>

                <p className="mt-1 text-xs leading-5 text-red-200/70">
                  {scanError}
                </p>
              </div>
            </div>

            {chainId !== ETHEREUM_CHAIN_ID &&
              walletAddress && (
                <button
                  type="button"
                  onClick={() => {
                    void switchToEthereum();
                  }}
                  className="rounded-xl border border-red-300/20 bg-red-300/10 px-3 py-2 text-xs font-semibold text-red-200 hover:bg-red-300/15"
                >
                  Switch to Ethereum
                </button>
              )}
          </div>
        )}

        {successMessage && !scanError && (
          <div className="mb-5 flex items-center gap-3 rounded-2xl border border-emerald-400/20 bg-emerald-400/5 px-4 py-3">
            <span className="text-emerald-300">
              <IconCheck />
            </span>

            <p className="text-sm text-emerald-200">
              {successMessage}
            </p>
          </div>
        )}

        {/* =================================================
            NETWORK / WALLET STATE
        ================================================= */}

        {!walletReady && (
          <section className="mb-6 rounded-3xl border border-white/10 bg-white/[0.035] p-6">
            <div className="flex flex-col gap-5 md:flex-row md:items-center md:justify-between">
              <div>
                <div className="flex items-center gap-2">
                  <span className="h-2.5 w-2.5 rounded-full bg-amber-400" />

                  <h3 className="font-semibold">
                    {walletAddress
                      ? "Switch to Ethereum Mainnet"
                      : "Connect your wallet to begin"}
                  </h3>
                </div>

                <p className="mt-2 max-w-2xl text-sm leading-6 text-slate-500">
                  WalletGuard reads public blockchain state.
                  It never asks for your private key or seed
                  phrase.
                </p>
              </div>

              {walletAddress ? (
                <button
                  type="button"
                  onClick={() => {
                    void switchToEthereum();
                  }}
                  className="rounded-xl bg-white px-4 py-2.5 text-sm font-bold text-slate-950 hover:bg-slate-200"
                >
                  Switch Network
                </button>
              ) : (
                <button
                  type="button"
                  onClick={() => {
                    void connectWallet();
                  }}
                  className="rounded-xl bg-cyan-400 px-4 py-2.5 text-sm font-bold text-slate-950 hover:bg-cyan-300"
                >
                  Connect MetaMask
                </button>
              )}
            </div>
          </section>
        )}

        {/* =================================================
            SECURITY OVERVIEW
        ================================================= */}

        <section className="mb-6">
          <div className="mb-3 flex flex-col gap-2 sm:flex-row sm:items-end sm:justify-between">
            <div>
              <p className="text-xs font-semibold uppercase tracking-[0.2em] text-slate-500">
                Security overview
              </p>

              <h3 className="mt-1 text-xl font-bold">
                Current wallet exposure
              </h3>
            </div>

            {lastScanAt && (
              <p className="text-xs text-slate-500">
                Last verified{" "}
                {formatTime(lastScanAt)}
              </p>
            )}
          </div>

          <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-5">
            <MetricCard
              title="Active approvals"
              value={summary.totalActive ?? 0}
              subtitle="Permissions currently detected"
              icon={<IconShield size={18} />}
            />

            <MetricCard
              title="Live exposure"
              value={activeExposureCount}
              subtitle="Approvals with wallet balance exposure"
              icon={<IconActivity size={18} />}
              emphasis="cyan"
            />

            <MetricCard
              title="High"
              value={summary.high ?? 0}
              subtitle="Immediate exposure requiring attention"
              icon={<IconAlert size={18} />}
              emphasis="red"
            />

            <MetricCard
              title="Review"
              value={summary.review ?? 0}
              subtitle="Permissions needing contextual review"
              icon={<IconEye size={18} />}
              emphasis="amber"
            />

            <MetricCard
              title="No exposure"
              value={summary.noExposure ?? 0}
              subtitle="Permission exists but balance exposure is zero"
              icon={<IconLock size={18} />}
              emphasis="green"
            />
          </div>
        </section>

        {/* =================================================
            PHASE 4 MONITOR
        ================================================= */}

        <section className="mb-6 rounded-3xl border border-white/10 bg-gradient-to-r from-white/[0.045] to-white/[0.02] p-5">
          <div className="flex flex-col gap-5 lg:flex-row lg:items-center lg:justify-between">
            <div className="flex gap-4">
              <div className="flex h-11 w-11 shrink-0 items-center justify-center rounded-2xl border border-violet-400/20 bg-violet-400/10 text-violet-300">
                <IconActivity size={21} />
              </div>

              <div>
                <div className="flex flex-wrap items-center gap-2">
                  <h3 className="font-semibold">
                    Continuous Security Monitor
                  </h3>

                  <span
                    className={`rounded-full px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider ${
                      monitorEnabled
                        ? "bg-emerald-400/10 text-emerald-300"
                        : "bg-white/5 text-slate-500"
                    }`}
                  >
                    {monitorEnabled
                      ? "Active"
                      : "Standby"}
                  </span>
                </div>

                <p className="mt-1 max-w-2xl text-xs leading-5 text-slate-500">
                  When enabled, WalletGuard re-scans the
                  connected wallet periodically and refreshes
                  live approval state. This is a monitoring
                  layer, not a substitute for transaction
                  simulation.
                </p>

                {monitorDelta && (
                  <div className="mt-2 flex flex-wrap gap-3 text-[11px]">
                    <span className="text-slate-500">
                      Active delta:{" "}
                      <span className="text-slate-300">
                        {monitorDelta.total > 0
                          ? `+${monitorDelta.total}`
                          : monitorDelta.total}
                      </span>
                    </span>

                    <span className="text-slate-500">
                      High delta:{" "}
                      <span className="text-slate-300">
                        {monitorDelta.high > 0
                          ? `+${monitorDelta.high}`
                          : monitorDelta.high}
                      </span>
                    </span>
                  </div>
                )}
              </div>
            </div>

            <div className="flex items-center gap-3">
              <span className="text-xs text-slate-500">
                Auto-check
              </span>

              <button
                type="button"
                role="switch"
                aria-checked={monitorEnabled}
                disabled={!walletReady}
                onClick={() =>
                  setMonitorEnabled(
                    (previous) => !previous
                  )
                }
                className={`relative h-7 w-12 rounded-full border transition ${
                  monitorEnabled
                    ? "border-cyan-300/30 bg-cyan-400/20"
                    : "border-white/10 bg-white/5"
                } disabled:cursor-not-allowed disabled:opacity-40`}
              >
                <span
                  className={`absolute top-1 h-5 w-5 rounded-full transition ${
                    monitorEnabled
                      ? "left-6 bg-cyan-300"
                      : "left-1 bg-slate-500"
                  }`}
                />
              </button>
            </div>
          </div>
        </section>

        {/* =================================================
            APPROVALS
        ================================================= */}

        <section className="overflow-hidden rounded-3xl border border-white/10 bg-white/[0.025]">
          <div className="border-b border-white/10 p-5 sm:p-6">
            <div className="flex flex-col gap-5 xl:flex-row xl:items-end xl:justify-between">
              <div>
                <p className="text-xs font-semibold uppercase tracking-[0.2em] text-slate-500">
                  Approval intelligence
                </p>

                <h3 className="mt-1 text-xl font-bold">
                  Active permissions
                </h3>

                <p className="mt-1 text-xs text-slate-500">
                  Showing {formatNumber(
                    filteredFindings.length
                  )} matching findings
                </p>
              </div>

              <div className="flex flex-col gap-2 sm:flex-row">
                <div className="relative">
                  <div className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-slate-500">
                    <IconSearch size={16} />
                  </div>

                  <input
                    value={searchQuery}
                    onChange={(event) => {
                      setSearchQuery(
                        event.target.value
                      );
                      setPage(1);
                    }}
                    placeholder="Search token or spender..."
                    className="h-10 w-full rounded-xl border border-white/10 bg-black/20 pl-9 pr-3 text-xs text-white outline-none placeholder:text-slate-600 focus:border-cyan-400/30 sm:w-64"
                  />
                </div>

                <select
                  value={riskFilter}
                  onChange={(event) => {
                    setRiskFilter(
                      event.target.value as
                        | "ALL"
                        | RiskLevel
                    );
                    setPage(1);
                  }}
                  className="h-10 rounded-xl border border-white/10 bg-[#0c121c] px-3 text-xs text-slate-300 outline-none"
                >
                  <option value="ALL">
                    All risk levels
                  </option>
                  <option value="HIGH">
                    High
                  </option>
                  <option value="REVIEW">
                    Review
                  </option>
                  <option value="LOW">
                    Low
                  </option>
                  <option value="NO_EXPOSURE">
                    No exposure
                  </option>
                </select>

                <select
                  value={classificationFilter}
                  onChange={(event) => {
                    setClassificationFilter(
                      event.target.value as
                        | "ALL"
                        | SpenderClassification
                    );
                    setPage(1);
                  }}
                  className="h-10 rounded-xl border border-white/10 bg-[#0c121c] px-3 text-xs text-slate-300 outline-none"
                >
                  <option value="ALL">
                    All spenders
                  </option>
                  <option value="UNKNOWN">
                    Unknown
                  </option>
                  <option value="KNOWN_PROTOCOL">
                    Protocols
                  </option>
                  <option value="KNOWN_INFRASTRUCTURE">
                    Infrastructure
                  </option>
                </select>

                <select
                  value={sortMode}
                  onChange={(event) => {
                    setSortMode(
                      event.target.value as
                        | "RISK"
                        | "EXPOSURE"
                        | "TOKEN"
                    );
                    setPage(1);
                  }}
                  className="h-10 rounded-xl border border-white/10 bg-[#0c121c] px-3 text-xs text-slate-300 outline-none"
                >
                  <option value="RISK">
                    Sort: Risk
                  </option>
                  <option value="EXPOSURE">
                    Sort: Exposure
                  </option>
                  <option value="TOKEN">
                    Sort: Token
                  </option>
                </select>
              </div>
            </div>
          </div>

          {/* TABLE */}
          <div className="overflow-x-auto">
            <table className="w-full min-w-[1050px] border-collapse">
              <thead>
                <tr className="border-b border-white/10 bg-black/10 text-left">
                  <th className="px-5 py-3 text-[10px] font-semibold uppercase tracking-wider text-slate-500">
                    Asset
                  </th>

                  <th className="px-5 py-3 text-[10px] font-semibold uppercase tracking-wider text-slate-500">
                    Spender
                  </th>

                  <th className="px-5 py-3 text-[10px] font-semibold uppercase tracking-wider text-slate-500">
                    Permission
                  </th>

                  <th className="px-5 py-3 text-[10px] font-semibold uppercase tracking-wider text-slate-500">
                    Current exposure
                  </th>

                  <th className="px-5 py-3 text-[10px] font-semibold uppercase tracking-wider text-slate-500">
                    Risk
                  </th>

                  <th className="px-5 py-3 text-right text-[10px] font-semibold uppercase tracking-wider text-slate-500">
                    Action
                  </th>
                </tr>
              </thead>

              <tbody>
                {visibleFindings.length === 0 ? (
                  <tr>
                    <td
                      colSpan={6}
                      className="px-6 py-16 text-center"
                    >
                      <div className="mx-auto flex max-w-md flex-col items-center">
                        <div className="flex h-14 w-14 items-center justify-center rounded-2xl border border-white/10 bg-white/5 text-slate-500">
                          {walletAddress ? (
                            <IconSearch size={24} />
                          ) : (
                            <IconWallet size={24} />
                          )}
                        </div>

                        <h4 className="mt-4 font-semibold">
                          {walletAddress
                            ? "No approval findings to display"
                            : "Connect a wallet to scan"}
                        </h4>

                        <p className="mt-2 text-xs leading-5 text-slate-500">
                          {walletAddress
                            ? "Run a scan or adjust your filters to see matching permissions."
                            : "WalletGuard needs a connected Ethereum Mainnet wallet before it can inspect approval state."}
                        </p>
                      </div>
                    </td>
                  </tr>
                ) : (
                  visibleFindings.map(
                    (finding, index) => (
                      <ApprovalRow
                        key={`${finding.token}-${finding.spender}-${index}`}
                        finding={finding}
                        onEvidence={() =>
                          setSelectedFinding(
                            finding
                          )
                        }
                        onRevoke={() =>
                          setRevokeTarget(
                            finding
                          )
                        }
                      />
                    )
                  )
                )}
              </tbody>
            </table>
          </div>

          {/* PAGINATION */}
          <div className="flex flex-col gap-3 border-t border-white/10 p-4 sm:flex-row sm:items-center sm:justify-between">
            <p className="text-xs text-slate-500">
              {filteredFindings.length === 0
                ? "0 results"
                : `Showing ${
                    (page - 1) * PAGE_SIZE + 1
                  }–${Math.min(
                    page * PAGE_SIZE,
                    filteredFindings.length
                  )} of ${formatNumber(
                    filteredFindings.length
                  )}`}
            </p>

            <div className="flex items-center gap-2">
              <button
                type="button"
                disabled={page <= 1}
                onClick={() =>
                  setPage((previous) =>
                    Math.max(1, previous - 1)
                  )
                }
                className="rounded-xl border border-white/10 px-3 py-2 text-xs text-slate-400 hover:bg-white/5 disabled:cursor-not-allowed disabled:opacity-30"
              >
                Previous
              </button>

              <span className="rounded-xl bg-white/5 px-3 py-2 text-xs text-slate-300">
                Page {page} / {totalPages}
              </span>

              <button
                type="button"
                disabled={page >= totalPages}
                onClick={() =>
                  setPage((previous) =>
                    Math.min(
                      totalPages,
                      previous + 1
                    )
                  )
                }
                className="rounded-xl border border-white/10 px-3 py-2 text-xs text-slate-400 hover:bg-white/5 disabled:cursor-not-allowed disabled:opacity-30"
              >
                Next
              </button>
            </div>
          </div>
        </section>

        {/* =================================================
            LOWER INFORMATION GRID
        ================================================= */}

        <section className="mt-6 grid gap-5 lg:grid-cols-[1fr_1fr]">
          {/* ACTIVITY */}
          <div className="rounded-3xl border border-white/10 bg-white/[0.025] p-5 sm:p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs font-semibold uppercase tracking-[0.2em] text-slate-500">
                  Resolution timeline
                </p>

                <h3 className="mt-1 text-lg font-bold">
                  Security activity
                </h3>
              </div>

              <IconActivity size={20} />
            </div>

            <div className="mt-5 space-y-3">
              {activity.length === 0 ? (
                <div className="rounded-2xl border border-dashed border-white/10 p-5 text-center">
                  <p className="text-xs text-slate-500">
                    Scan, verify, or revoke an approval
                    to populate the security timeline.
                  </p>
                </div>
              ) : (
                activity.slice(0, 7).map((item) => (
                  <div
                    key={item.id}
                    className="flex gap-3 rounded-2xl border border-white/5 bg-black/15 p-3"
                  >
                    <ActivityDot
                      type={item.type}
                    />

                    <div className="min-w-0 flex-1">
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <p className="text-xs font-semibold text-slate-200">
                          {item.title}
                        </p>

                        <span className="text-[10px] text-slate-600">
                          {formatTime(item.time)}
                        </span>
                      </div>

                      <p className="mt-1 text-[11px] leading-5 text-slate-500">
                        {item.description}
                      </p>

                      {item.hash && (
                        <p className="mt-1 font-mono text-[10px] text-cyan-400/70">
                          {shortenHash(item.hash)}
                        </p>
                      )}
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>

          {/* TRANSPARENCY */}
          <div className="rounded-3xl border border-white/10 bg-white/[0.025] p-5 sm:p-6">
            <p className="text-xs font-semibold uppercase tracking-[0.2em] text-slate-500">
              Verification transparency
            </p>

            <h3 className="mt-1 text-lg font-bold">
              How WalletGuard reaches a finding
            </h3>

            <div className="mt-5 space-y-3">
              <TransparencyRow
                title="Historical approval discovery"
                value={
                  scanInfo?.source ??
                  "Routescan transaction history"
                }
              />

              <TransparencyRow
                title="Live blockchain state"
                value={
                  scanInfo?.liveStateVerified
                    ? "Verified"
                    : "Not confirmed"
                }
                positive={
                  scanInfo?.liveStateVerified
                }
              />

              <TransparencyRow
                title="Exposure formula"
                value={
                  scanInfo?.exposureFormula ??
                  "min(live allowance, wallet balance)"
                }
              />

              <TransparencyRow
                title="Historical scan limit"
                value={`${formatNumber(
                  scanInfo?.historicalTransactionLimit ??
                    5000
                )} transactions`}
              />

              <TransparencyRow
                title="USD pricing"
                value={
                  scanInfo?.usdPricing
                    ? "Enabled"
                    : "Not inferred"
                }
              />
            </div>

            <div className="mt-5 rounded-2xl border border-cyan-400/10 bg-cyan-400/5 p-4">
              <p className="text-xs font-semibold text-cyan-200">
                Important distinction
              </p>

              <p className="mt-1 text-[11px] leading-5 text-cyan-100/60">
                An active permission is not automatically
                current financial exposure. WalletGuard
                compares the live allowance with the
                wallet&apos;s live token balance. Permit2
                internal permissions may require separate
                analysis beyond the base ERC-20 approval.
              </p>
            </div>
          </div>
        </section>

        {/* =================================================
            FOOTER
        ================================================= */}

        <footer className="mt-8 border-t border-white/10 py-6">
          <div className="flex flex-col gap-3 text-[11px] leading-5 text-slate-600 sm:flex-row sm:items-center sm:justify-between">
            <p>
              WalletGuard • Ethereum Mainnet •
              Non-custodial approval security
            </p>

            <p>
              Live state is verified on-chain before
              exposure is presented.
            </p>
          </div>
        </footer>
      </div>

      {/* ===================================================
          EVIDENCE MODAL
      =================================================== */}

      {selectedFinding && (
        <EvidenceModal
          finding={selectedFinding}
          onClose={() =>
            setSelectedFinding(null)
          }
          onRevoke={() => {
            setSelectedFinding(null);
            setRevokeTarget(selectedFinding);
          }}
        />
      )}

      {/* ===================================================
          REVOKE CONFIRMATION
      =================================================== */}

      {revokeTarget && (
        <RevokeModal
          finding={revokeTarget}
          revoking={revoking}
          onCancel={() => {
            if (!revoking) {
              setRevokeTarget(null);
            }
          }}
          onConfirm={() => {
            void revokeApproval(revokeTarget);
          }}
        />
      )}
    </main>
  );
}

/* =========================================================
   METRIC CARD
========================================================= */

function MetricCard({
  title,
  value,
  subtitle,
  icon,
  emphasis = "default",
}: {
  title: string;
  value: number;
  subtitle: string;
  icon: React.ReactNode;
  emphasis?: "default" | "cyan" | "red" | "amber" | "green";
}) {
  const emphasisClass = {
    default: "text-slate-200",
    cyan: "text-cyan-300",
    red: "text-red-300",
    amber: "text-amber-300",
    green: "text-emerald-300",
  }[emphasis];

  return (
    <div className="rounded-2xl border border-white/10 bg-white/[0.035] p-4">
      <div className="flex items-center justify-between">
        <span className="text-slate-500">
          {icon}
        </span>

        <span
          className={`text-2xl font-bold tracking-tight ${emphasisClass}`}
        >
          {formatNumber(value)}
        </span>
      </div>

      <p className="mt-3 text-xs font-semibold text-slate-300">
        {title}
      </p>

      <p className="mt-1 text-[10px] leading-4 text-slate-600">
        {subtitle}
      </p>
    </div>
  );
}

/* =========================================================
   APPROVAL ROW
========================================================= */

function ApprovalRow({
  finding,
  onEvidence,
  onRevoke,
}: {
  finding: Finding;
  onEvidence: () => void;
  onRevoke: () => void;
}) {
  const risk = getRisk(finding);

  const revoked =
    finding.status === "REVOKED";

  const verifying =
    finding.status === "VERIFYING";

  return (
    <tr className="border-b border-white/5 transition hover:bg-white/[0.025]">
      <td className="px-5 py-4">
        <div className="flex items-center gap-3">
          <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl border border-white/10 bg-white/5 text-xs font-bold text-slate-300">
            {displaySymbol(
              finding.tokenSymbol
            ).slice(0, 3)}
          </div>

          <div className="min-w-0">
            <p className="truncate text-sm font-semibold text-slate-200">
              {displaySymbol(
                finding.tokenSymbol
              )}
            </p>

            <p className="mt-0.5 font-mono text-[10px] text-slate-600">
              {shortenAddress(finding.token)}
            </p>
          </div>
        </div>
      </td>

      <td className="px-5 py-4">
        <div>
          <p className="text-xs font-semibold text-slate-300">
            {finding.spenderLabel ||
              "Unknown spender"}
          </p>

          <p className="mt-1 font-mono text-[10px] text-slate-600">
            {shortenAddress(
              finding.spender
            )}
          </p>

          <p className="mt-1 text-[9px] uppercase tracking-wider text-slate-600">
            {getClassificationLabel(
              finding.spenderClassification
            )}
          </p>
        </div>
      </td>

      <td className="px-5 py-4">
        <div>
          <span
            className={`inline-flex rounded-lg border px-2 py-1 text-[10px] font-semibold ${
              finding.unlimited
                ? "border-amber-400/20 bg-amber-400/5 text-amber-300"
                : "border-white/10 bg-white/5 text-slate-400"
            }`}
          >
            {finding.unlimited
              ? "Unlimited"
              : "Limited"}
          </span>

          <p className="mt-2 max-w-[180px] truncate text-[10px] text-slate-600">
            {finding.allowanceFormatted ??
              finding.allowance ??
              "Unknown"}
          </p>
        </div>
      </td>

      <td className="px-5 py-4">
        <div>
          <p
            className={`text-sm font-semibold ${
              getExposureNumber(finding) > 0
                ? "text-cyan-300"
                : "text-slate-400"
            }`}
          >
            {finding.currentExposureFormatted ??
              "0"}
          </p>

          <p className="mt-1 text-[10px] text-slate-600">
            Wallet balance{" "}
            {finding.walletBalanceFormatted ??
              finding.walletBalance ??
              "—"}
          </p>
        </div>
      </td>

      <td className="px-5 py-4">
        <RiskBadge risk={risk} />
      </td>

      <td className="px-5 py-4">
        <div className="flex justify-end gap-2">
          <button
            type="button"
            onClick={onEvidence}
            className="inline-flex items-center gap-1.5 rounded-xl border border-white/10 bg-white/[0.03] px-3 py-2 text-[10px] font-semibold text-slate-300 transition hover:bg-white/10"
          >
            <IconEye size={14} />
            Evidence
          </button>

          <button
            type="button"
            disabled={revoked || verifying}
            onClick={onRevoke}
            className={`inline-flex items-center gap-1.5 rounded-xl px-3 py-2 text-[10px] font-bold transition ${
              revoked
                ? "cursor-not-allowed border border-emerald-400/10 bg-emerald-400/5 text-emerald-400/50"
                : verifying
                ? "cursor-not-allowed bg-white/5 text-slate-600"
                : "bg-red-400/10 text-red-300 hover:bg-red-400/15"
            }`}
          >
            {verifying ? (
              <IconRefresh
                size={14}
                spinning
              />
            ) : revoked ? (
              <IconCheck size={14} />
            ) : (
              <IconLock size={14} />
            )}

            {verifying
              ? "Verifying"
              : revoked
              ? "Revoked"
              : "Revoke"}
          </button>
        </div>
      </td>
    </tr>
  );
}

/* =========================================================
   RISK BADGE
========================================================= */

function RiskBadge({
  risk,
}: {
  risk: RiskLevel;
}) {
  const styles = {
    HIGH: {
      wrapper:
        "border-red-400/20 bg-red-400/10 text-red-300",
      dot: "bg-red-400",
    },

    REVIEW: {
      wrapper:
        "border-amber-400/20 bg-amber-400/10 text-amber-300",
      dot: "bg-amber-400",
    },

    LOW: {
      wrapper:
        "border-cyan-400/20 bg-cyan-400/10 text-cyan-300",
      dot: "bg-cyan-400",
    },

    NO_EXPOSURE: {
      wrapper:
        "border-emerald-400/20 bg-emerald-400/10 text-emerald-300",
      dot: "bg-emerald-400",
    },
  }[risk];

  return (
    <div>
      <span
        className={`inline-flex items-center gap-1.5 rounded-lg border px-2 py-1 text-[10px] font-semibold ${styles.wrapper}`}
      >
        <span
          className={`h-1.5 w-1.5 rounded-full ${styles.dot}`}
        />

        {getRiskLabel(risk)}
      </span>

      <p className="mt-1 max-w-[160px] text-[9px] leading-4 text-slate-600">
        {getRiskDescription(risk)}
      </p>
    </div>
  );
}

/* =========================================================
   EVIDENCE MODAL
========================================================= */

function EvidenceModal({
  finding,
  onClose,
  onRevoke,
}: {
  finding: Finding;
  onClose: () => void;
  onRevoke: () => void;
}) {
  const risk = getRisk(finding);

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4 backdrop-blur-sm"
      onMouseDown={(event) => {
        if (event.target === event.currentTarget) {
          onClose();
        }
      }}
    >
      <div className="max-h-[90vh] w-full max-w-3xl overflow-y-auto rounded-3xl border border-white/10 bg-[#0b111b] shadow-2xl shadow-black/50">
        <div className="sticky top-0 z-10 flex items-center justify-between border-b border-white/10 bg-[#0b111b]/95 px-5 py-4 backdrop-blur sm:px-6">
          <div>
            <p className="text-[10px] font-semibold uppercase tracking-[0.2em] text-cyan-400">
              On-chain evidence
            </p>

            <h3 className="mt-1 text-lg font-bold">
              {displaySymbol(
                finding.tokenSymbol
              )}{" "}
              approval
            </h3>
          </div>

          <button
            type="button"
            onClick={onClose}
            className="rounded-xl p-2 text-slate-500 hover:bg-white/5 hover:text-white"
          >
            <IconX />
          </button>
        </div>

        <div className="space-y-5 p-5 sm:p-6">
          <div className="grid gap-3 sm:grid-cols-2">
            <EvidenceCard
              label="Risk state"
              value={getRiskLabel(risk)}
            />

            <EvidenceCard
              label="Permission"
              value={
                finding.unlimited
                  ? "Effectively unlimited"
                  : "Limited allowance"
              }
            />

            <EvidenceCard
              label="Current exposure"
              value={
                finding.currentExposureFormatted ??
                "0"
              }
            />

            <EvidenceCard
              label="Wallet balance"
              value={
                finding.walletBalanceFormatted ??
                "Unknown"
              }
            />
          </div>

          <div className="rounded-2xl border border-white/10 bg-black/20 p-4">
            <p className="text-xs font-semibold text-slate-300">
              Why this matters
            </p>

            <p className="mt-2 text-sm leading-6 text-slate-400">
              {finding.explanation ||
                "WalletGuard detected an active ERC-20 permission and evaluated its current exposure using the live allowance and wallet balance."}
            </p>
          </div>

          <div>
            <p className="mb-3 text-xs font-semibold uppercase tracking-wider text-slate-500">
              Risk vector
            </p>

            <div className="grid gap-2 sm:grid-cols-2">
              <VectorRow
                label="Permission"
                value={
                  finding.riskVector?.permission
                }
              />

              <VectorRow
                label="Asset exposure"
                value={
                  finding.riskVector
                    ?.assetExposure
                }
              />

              <VectorRow
                label="Spender risk"
                value={
                  finding.riskVector
                    ?.spenderRisk
                }
              />

              <VectorRow
                label="Activity risk"
                value={
                  finding.riskVector
                    ?.activityRisk
                }
              />

              <VectorRow
                label="Contract risk"
                value={
                  finding.riskVector
                    ?.contractRisk
                }
              />

              <VectorRow
                label="Data confidence"
                value={
                  finding.riskVector
                    ?.dataConfidence
                }
              />
            </div>
          </div>
                    {/* =====================================================
              SECURITY INTELLIGENCE
          ====================================================== */}

          {finding.securityIntelligence && (
            <div className="rounded-2xl border border-cyan-400/15 bg-cyan-400/[0.035] p-5">
              <div className="flex items-center gap-2">
                <span className="text-lg">🛡️</span>

                <div>
                  <p className="text-sm font-semibold text-cyan-200">
                    Security Intelligence
                  </p>

                  <p className="mt-0.5 text-[10px] text-slate-500">
                    Historical and behavioral evidence around this permission
                  </p>
                </div>
              </div>

              <div className="mt-4 grid gap-2 sm:grid-cols-2">
                <VectorRow
                  label="Approval age"
                  value={
                    finding.securityIntelligence.approvalAgeDays === null
                      ? "Unknown"
                      : finding.securityIntelligence.approvalAgeDays === 0
                        ? "Less than 1 day"
                        : `${finding.securityIntelligence.approvalAgeDays} days`
                  }
                />

                <VectorRow
                  label="Approval age band"
                  value={
                    finding.securityIntelligence.approvalAgeBand
                  }
                />

                <VectorRow
                  label="Wallet → spender"
                  value={
                    finding.securityIntelligence.activityStatus === "ACTIVE"
                      ? "Interaction found"
                      : finding.securityIntelligence.activityStatus ===
                          "NO_INTERACTION_FOUND"
                        ? "No interaction found"
                        : "Unknown"
                  }
                />

                <VectorRow
                  label="Interaction count"
                  value={
                    finding.securityIntelligence
                      .spenderInteractionCount === null
                      ? "Unknown"
                      : String(
                          finding.securityIntelligence
                            .spenderInteractionCount
                        )
                  }
                />
              </div>

              <div className="mt-4 rounded-xl border border-white/5 bg-black/20 p-3">
                <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-600">
                  Activity interpretation
                </p>

                <p className="mt-1 text-xs leading-5 text-slate-400">
                  {finding.securityIntelligence.activityStatus === "ACTIVE"
                    ? "The scanned wallet has a recorded transaction directly interacting with this spender."
                    : finding.securityIntelligence.activityStatus ===
                        "NO_INTERACTION_FOUND"
                      ? "No direct wallet-to-spender interaction was found in the scanned transaction history."
                      : "Historical coverage reached the configured transaction limit, so absence of an interaction cannot be treated as proof that none occurred."}
                </p>
              </div>

              {finding.securityIntelligence.lastSpenderInteraction && (
                <div className="mt-3">
                  <VectorRow
                    label="Last interaction"
                    value={new Date(
                      finding.securityIntelligence.lastSpenderInteraction * 1000
                    ).toLocaleString()}
                  />
                </div>
              )}

              {finding.securityIntelligence.evidence.length > 0 && (
                <div className="mt-4">
                  <p className="mb-2 text-[10px] font-semibold uppercase tracking-wider text-slate-600">
                    Evidence
                  </p>

                  <div className="space-y-2">
                    {finding.securityIntelligence.evidence.map(
                      (item, index) => (
                        <div
                          key={`${item.type}-${item.timestamp ?? "none"}-${index}`}
                          className="rounded-xl border border-white/5 bg-black/15 px-3 py-2.5"
                        >
                          <div className="flex items-start justify-between gap-3">
                            <p className="text-xs text-slate-300">
                              {item.description}
                            </p>

                            <span className="shrink-0 rounded-full border border-white/10 bg-white/5 px-2 py-0.5 text-[9px] font-semibold uppercase tracking-wider text-slate-500">
                              {item.type.replaceAll("_", " ")}
                            </span>
                          </div>

                          {item.txHash && (
                            <p className="mt-1 font-mono text-[9px] text-cyan-400/60">
                              {shortenHash(item.txHash)}
                            </p>
                          )}
                        </div>
                      )
                    )}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* =====================================================
              PERMIT2 INTELLIGENCE
          ====================================================== */}

          {finding.permit2Intelligence?.isPermit2 && (
            <div className="rounded-2xl border border-violet-400/15 bg-violet-400/[0.035] p-5">
              <div className="flex items-center gap-2">
                <span className="text-lg">🔐</span>

                <div>
                  <p className="text-sm font-semibold text-violet-200">
                    Permit2 Intelligence
                  </p>

                  <p className="mt-0.5 text-[10px] text-slate-500">
                    Additional context for the Permit2 infrastructure layer
                  </p>
                </div>
              </div>

              <div className="mt-4 grid gap-2 sm:grid-cols-2">
                <VectorRow
                  label="Permit2 detected"
                  value="Yes"
                />

                <VectorRow
                  label="Base ERC-20 approval"
                  value={
                    finding.permit2Intelligence.baseApprovalVerified
                      ? "Verified on-chain"
                      : "Not verified"
                  }
                />

                <VectorRow
                  label="Internal permission"
                  value={
                    finding.permit2Intelligence.internalPermissionFound
                      ? "Found"
                      : "Not established"
                  }
                />

                <VectorRow
                  label="Internal spender"
                  value={
                    finding.permit2Intelligence.spender
                      ? shortenAddress(
                          finding.permit2Intelligence.spender,
                          8
                        )
                      : "Not established"
                  }
                />
              </div>

              {finding.permit2Intelligence.internalPermissionFound ? (
                <div className="mt-4 grid gap-2 sm:grid-cols-3">
                  <VectorRow
                    label="Amount"
                    value={
                      finding.permit2Intelligence.amount ?? "Unknown"
                    }
                  />

                  <VectorRow
                    label="Expiration"
                    value={
                      finding.permit2Intelligence.expiration
                        ? new Date(
                            finding.permit2Intelligence.expiration * 1000
                          ).toLocaleString()
                        : "Unknown"
                    }
                  />

                  <VectorRow
                    label="Nonce"
                    value={
                      finding.permit2Intelligence.nonce === null
                        ? "Unknown"
                        : String(
                            finding.permit2Intelligence.nonce
                          )
                    }
                  />
                </div>
              ) : (
                <div className="mt-4 rounded-xl border border-violet-400/10 bg-violet-400/5 p-3">
                  <p className="text-xs leading-5 text-violet-100/70">
                    {finding.permit2Intelligence.reason ??
                      "The base ERC-20 approval to Permit2 is verified, but a specific internal Permit2 permission was not established from the available evidence."}
                  </p>
                </div>
              )}
            </div>
          )}
          <div>
            <p className="mb-3 text-xs font-semibold uppercase tracking-wider text-slate-500">
              Addresses
            </p>

            <div className="space-y-2">
              <AddressRow
                label="Token"
                address={finding.token}
              />

              <AddressRow
                label="Spender"
                address={finding.spender}
              />
            </div>
          </div>

          <div>
            <p className="mb-3 text-xs font-semibold uppercase tracking-wider text-slate-500">
              Approval evidence
            </p>

            <div className="space-y-2">
              <AddressRow
                label="Transaction"
                address={
                  finding.approvalTransactionHash
                }
                isHash
              />

              <AddressRow
                label="Block"
                address={
                  finding.approvalBlockNumber
                    ? String(
                        finding.approvalBlockNumber
                      )
                    : undefined
                }
                plain
              />

              <AddressRow
                label="Timestamp"
                address={
                  finding.approvalTimestamp
                    ? String(
                        finding.approvalTimestamp
                      )
                    : undefined
                }
                plain
              />
            </div>
          </div>

          <div className="flex flex-col-reverse gap-2 border-t border-white/10 pt-5 sm:flex-row sm:justify-end">
            <button
              type="button"
              onClick={onClose}
              className="rounded-xl border border-white/10 px-4 py-2.5 text-xs font-semibold text-slate-300 hover:bg-white/5"
            >
              Close
            </button>

            {finding.status !== "REVOKED" && (
              <button
                type="button"
                onClick={onRevoke}
                className="inline-flex items-center justify-center gap-2 rounded-xl bg-red-400/10 px-4 py-2.5 text-xs font-bold text-red-300 hover:bg-red-400/15"
              >
                <IconLock size={15} />
                Revoke approval
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}


function RevokeModal({
  finding,
  revoking,
  onCancel,
  onConfirm,
}: {
  finding: Finding;
  revoking: boolean;
  onCancel: () => void;
  onConfirm: () => void;
}) {
  return (
    <div
      className="fixed inset-0 z-[60] flex items-center justify-center bg-black/75 p-4 backdrop-blur-sm"
      onMouseDown={(event) => {
        if (
          event.target === event.currentTarget &&
          !revoking
        ) {
          onCancel();
        }
      }}
    >
      <div className="w-full max-w-md rounded-3xl border border-white/10 bg-[#0b111b] p-6 shadow-2xl shadow-black/60">
        <div className="flex h-12 w-12 items-center justify-center rounded-2xl border border-red-400/20 bg-red-400/10 text-red-300">
          <IconLock size={22} />
        </div>

        <h3 className="mt-5 text-xl font-bold">
          Revoke this approval?
        </h3>

        <p className="mt-2 text-sm leading-6 text-slate-500">
          WalletGuard will submit an ERC-20{" "}
          <span className="font-mono text-slate-300">
            approve(spender, 0)
          </span>{" "}
          transaction through MetaMask.
        </p>

        <div className="mt-5 rounded-2xl border border-white/10 bg-black/20 p-4">
          <div className="flex items-center justify-between gap-3">
            <span className="text-xs text-slate-500">
              Token
            </span>

            <span className="text-sm font-semibold text-slate-200">
              {displaySymbol(
                finding.tokenSymbol
              )}
            </span>
          </div>

          <div className="mt-3 flex items-center justify-between gap-3">
            <span className="text-xs text-slate-500">
              Spender
            </span>

            <span className="font-mono text-xs text-slate-300">
              {shortenAddress(
                finding.spender
              )}
            </span>
          </div>

          <div className="mt-3 flex items-center justify-between gap-3">
            <span className="text-xs text-slate-500">
              Current exposure
            </span>

            <span className="text-sm font-semibold text-cyan-300">
              {finding.currentExposureFormatted ??
                "0"}
            </span>
          </div>
        </div>

        <div className="mt-4 rounded-2xl border border-amber-400/10 bg-amber-400/5 p-3">
          <p className="text-[11px] leading-5 text-amber-200/70">
            MetaMask will ask you to approve the
            transaction. WalletGuard never receives your
            private key or seed phrase.
          </p>
        </div>

        <div className="mt-6 flex flex-col-reverse gap-2 sm:flex-row sm:justify-end">
          <button
            type="button"
            disabled={revoking}
            onClick={onCancel}
            className="rounded-xl border border-white/10 px-4 py-2.5 text-xs font-semibold text-slate-300 hover:bg-white/5 disabled:opacity-40"
          >
            Cancel
          </button>

          <button
            type="button"
            disabled={revoking}
            onClick={onConfirm}
            className="inline-flex items-center justify-center gap-2 rounded-xl bg-red-400 px-4 py-2.5 text-xs font-bold text-slate-950 hover:bg-red-300 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {revoking && (
              <IconRefresh
                size={14}
                spinning
              />
            )}

            {revoking
              ? "Waiting for confirmation..."
              : "Continue to MetaMask"}
          </button>
        </div>
      </div>
    </div>
  );
}


function EvidenceCard({
  label,
  value,
}: {
  label: string;
  value: string;
}) {
  return (
    <div className="rounded-2xl border border-white/10 bg-black/15 p-4">
      <p className="text-[10px] uppercase tracking-wider text-slate-600">
        {label}
      </p>

      <p className="mt-2 text-sm font-semibold text-slate-200">
        {value}
      </p>
    </div>
  );
}


function VectorRow({
  label,
  value,
}: {
  label: string;
  value?: string;
}) {
  return (
    <div className="flex items-start justify-between gap-4 rounded-xl border border-white/5 bg-white/[0.02] px-3 py-2.5">
      <span className="text-[11px] text-slate-500">
        {label}
      </span>

      <span className="text-right text-[11px] font-medium text-slate-300">
        {value || "Not available"}
      </span>
    </div>
  );
}

function AddressRow({
  label,
  address,
  isHash = false,
  plain = false,
}: {
  label: string;
  address?: string;
  isHash?: boolean;
  plain?: boolean;
}) {
  const display = !address
    ? "Not available"
    : plain
    ? address
    : isHash
    ? shortenHash(address)
    : shortenAddress(address, 8);

  return (
    <div className="flex items-center justify-between gap-4 rounded-xl border border-white/5 bg-black/15 px-3 py-2.5">
      <span className="text-[11px] text-slate-600">
        {label}
      </span>

      <span className="max-w-[65%] truncate font-mono text-[10px] text-slate-400">
        {display}
      </span>
    </div>
  );
}


function TransparencyRow({
  title,
  value,
  positive,
}: {
  title: string;
  value: string;
  positive?: boolean;
}) {
  return (
    <div className="flex items-center justify-between gap-4 border-b border-white/5 pb-3">
      <span className="text-xs text-slate-500">
        {title}
      </span>

      <span
        className={`max-w-[55%] text-right text-[11px] ${
          positive
            ? "text-emerald-300"
            : "text-slate-300"
        }`}
      >
        {value}
      </span>
    </div>
  );
}


function ActivityDot({
  type,
}: {
  type: ActivityItem["type"];
}) {
  const classes = {
    SCAN: "bg-cyan-400",
    REVOKE: "bg-red-400",
    VERIFY: "bg-emerald-400",
    INFO: "bg-violet-400",
    ERROR: "bg-amber-400",
  };

  return (
    <span
      className={`mt-1 h-2 w-2 shrink-0 rounded-full ${classes[type]}`}
    />
  );
}