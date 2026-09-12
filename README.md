# Marfani Steels — Container Cost Ledger

A live dashboard for the container costing / shipment tracking workbook.
Workbook rows are stored in PostgreSQL so authorized users can view the same
data from different locations.

## Run locally

```bash
npm install
npm start
```

Then open http://localhost:3000

## Deploy to Render

1. Push this folder to a new GitHub repository (root of the repo should
   contain `server.js`, `package.json`, `render.yaml`, and `public/index.html`).
2. Go to https://render.com, sign in, click **New → Blueprint**, and point it
   at this repo. Render will read `render.yaml` and configure everything
   automatically (build command `npm install`, start command `npm start`).
   - If you'd rather set it up by hand instead of using the blueprint,
     choose **New → Web Service**, connect the repo, and set:
     - Build Command: `npm install`
     - Start Command: `npm start`
3. Render deploys and gives you a URL like `dashboard-1.onrender.com`
   (rename it under Settings → Name if you want that exact address).
  The Blueprint also creates a PostgreSQL database and supplies its connection
  string to the web service as `DATABASE_URL`.
  Set these additional environment variables in Render before testing login:
  `APP_USERNAME`, `APP_PASSWORD`, and `SESSION_SECRET`. Use a long random
  value for `SESSION_SECRET` and never commit these values to the repository.

## Connecting your live Excel data

Once the site is live, open it and either:

- **Drag your `.xlsm`/`.xlsx` file directly onto the "drop file" area** —
  always works, refreshes instantly, no setup needed.
- **Paste a direct-download link** (from Google Drive / OneDrive, set to
  "anyone with the link") into the "Cloud file link" field and hit
  **Sync now**. Turn on auto-refresh to have it re-check periodically.

After an import succeeds, the rows are saved in PostgreSQL and are available
to other users opening the dashboard. Configure authentication before sharing
the URL publicly. The app login protects the dashboard and its data API.

Google Drive direct-download format:
`https://drive.google.com/uc?export=download&id=FILE_ID`

## Sheets it reads

- `Shipmement Costing` — main container/shipment cost table
- `Daywise` — weekly expense chart

If your sheet names change, update the matching strings in
`public/index.html` inside `parseWorkbook()`.
