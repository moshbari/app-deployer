# App Deployer - Claude Code Instructions

## Project Overview
Node.js/Express app that lets users deploy mini web apps to a VPS.
- Server: `server.js` (Express on port 3000)
- Frontend: `public/` (vanilla HTML/CSS/JS)
- Deployed apps live in `data/apps/`
- Template for new apps: `template/`
- Production URL: https://apps.heychatmate.com

## Workflow for Claude Sessions

### Branch & PR Strategy
1. Create a `claude/*` feature branch for all changes
2. Commit with clear messages explaining "why" not "what"
3. Push the branch and create a PR against `main`
4. The PR will be **auto-approved and auto-merged** by GitHub Actions (see `.github/workflows/auto-merge.yml`)
5. After merge, the deploy workflow auto-deploys to the VPS

### No manual merge needed
PRs from `claude/*` branches are automatically merged. Just push and create the PR.

## Key Files
- `server.js` - Main server, API routes, deploy logic
- `public/index.html` - Main UI (single page app)
- `public/style.css` - Styles
- `public/app.js` - Frontend JavaScript
- `template/` - Vite+React template for deployed apps
- `.github/workflows/deploy.yml` - CD pipeline to VPS
- `.github/workflows/auto-merge.yml` - Auto-merge for Claude PRs

## Development Notes
- The server uses `data/` directory for persistent state (apps, users) - never delete this in production
- Health check endpoint: `GET /health`
- Server has crash recovery via `uncaughtException` and `unhandledRejection` handlers
- Deploy builds run `npm install` and `npx vite build` inside `template/`
