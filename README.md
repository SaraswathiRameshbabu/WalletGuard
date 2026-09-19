# 🛡️ WalletGuard
### 🔴 [🚀 Live Demo](https://walletguardsaraswathi-9t07zaaf2-s-5944.vercel.app/)

### Active Approval Security & Revocation for Web3 Wallets

WalletGuard helps users discover, verify, understand, and revoke active ERC-20 token approvals that may expose their assets.

## 🚀 Key Features

- 🔍 **Active Approval Detection** — Finds currently active ERC-20 approvals from wallet transaction history.
- ⛓️ **Live On-Chain Verification** — Verifies current allowance and token balance directly on Ethereum.
- 💰 **Real Asset Exposure** — Calculates exposure using `min(allowance, wallet balance)` instead of treating allowance as exposure.
- 🧠 **Risk Vector** — Explains risk across Permission, Asset Exposure, Spender Risk, Activity Risk, Contract Risk, and Data Confidence.
- 🕵️ **Security Intelligence** — Analyzes approval age, wallet → spender interactions, interaction count, recent activity, and historical evidence.
- 🔐 **Permit2 Awareness** — Detects Permit2-related approvals and clearly distinguishes verified ERC-20 approval from unverified internal permissions.
- 🏷️ **Spender Classification** — Identifies known protocols/infrastructure and flags unknown spenders for review.
- 👛 **Read-Only Wallet Scan** — Scan any public Ethereum wallet without connecting MetaMask.
- 🦊 **MetaMask Integration** — Connect your wallet for transaction-based actions.
- 🧹 **One-Click Revocation** — Revoke ERC-20 approvals using `approve(spender, 0)`.
- ✅ **Revocation Verification** — Rechecks the blockchain after a transaction to confirm the approval was removed.
- 🔄 **Continuous Monitoring** — Periodically rescans the wallet for changes in approval exposure.
- 📋 **Evidence-Based Explanations** — Shows why an approval is considered risky instead of relying on an unexplained score.
- ⚡ **Multicall Optimization** — Batches on-chain allowance, balance, symbol, and decimal reads for efficient scanning.

## 🛠️ Tech Stack

**Frontend:** Next.js, React, TypeScript, Tailwind CSS  
**Blockchain:** Ethereum Mainnet, viem, Alchemy RPC  
**Transaction History:** Routescan  
**Wallet:** MetaMask


## 💻 Run Locally

### Prerequisites

- Node.js 18+
- npm
- Alchemy Ethereum Mainnet API key
- MetaMask *(required only for wallet connection and approval revocation)*

### 1. Clone the repository

```bash
git clone https://github.com/SaraswathiRameshbabu/WalletGuard.git
cd WalletGuard
````

### 2. Install dependencies

```bash
npm install
```

### 3. Configure environment variables

Create a `.env.local` file in the project root:

```env
ALCHEMY_API_KEY=your_alchemy_api_key
```

### 4. Start the development server

```bash
npm run dev
```

### 5. Open WalletGuard

Visit:

```text
http://localhost:3000
```

### 6. Production build

To verify and run the production build:

```bash
npm run build
npm run start
```

Then open:

```text
http://localhost:3000
```

> **Note:** WalletGuard can scan public Ethereum wallets without MetaMask. MetaMask is required only for connecting a wallet and revoking approvals.

