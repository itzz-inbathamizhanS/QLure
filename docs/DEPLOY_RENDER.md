# Hosted demo on Render

This page covers the hosted QLure demo: a Render web service that shows the dashboard with sample
data. The definition is [render.yaml](../render.yaml). The build steps are
[tools/seed_demo.py](../tools/seed_demo.py) and [tools/prepare_hosted_demo.py](../tools/prepare_hosted_demo.py).

Service: `qlure-demo` (Render id `srv-db4rlgh42hec73eob130`, free plan, region Oregon, branch `main`).
Dashboard for the service: https://dashboard.render.com/web/srv-db4rlgh42hec73eob130

## 1. What is deployed and why

- **Read-only demo with sample data, not a live honeypot.** The service runs the dashboard only
  (`dashboard.app:app`). No decoy listens on it.
- **Sample data is built at deploy time.** The build runs `seed_demo.py --force`, which drives the
  decoys in-process and writes 100 events, 10 sessions and 7 actors (4 Noteworthy, 4 Suspicious,
  2 Benign). The hash chain is verified during the build. The data is fake and uses documentation
  addresses.
- **Judge mode is on.** `prepare_hosted_demo.py` switches it on through the settings API, audited
  as `deploy-script`. While it is on, settings changes and Clear All are refused, and session
  labels are read-only. The judge mode switch itself can still be changed on the settings page;
  the next deploy turns it on again.
- **Rebuilt on every deploy.** The database and logs are regenerated each time.
- **No SSH, FTP, MySQL or Redis decoys.** A Render web service exposes only public HTTP(S), so
  those listeners cannot be reached from the internet on Render. A public honeypot is out of
  scope: QLure is designed to run on localhost.
- `QLURE_LIVE=0`, so the live feed does not run in the service.

## 2. URL and login

- Open https://qlure-demo.onrender.com and sign in at the login page. The form asks only for the
  password.
- The password is the value of `QLURE_DASHBOARD_PASSWORD`. Read it in the service's
  **Environment** tab in the Render dashboard. Never commit it or paste it into the repository.
- The login cookie is `Secure`, so it works only over HTTPS.

## 3. Auto-deploy, manual deploy and logs

- **Auto-deploy:** a push to `main` makes Render rebuild the service. The build regenerates the
  sample data, then the service starts with uvicorn on `$PORT`.
- **Manual redeploy:** in the Render dashboard, open the service and choose **Manual Deploy**, then
  deploy the latest commit. Use this after changing an environment variable.
- **Logs:** open the service in the Render dashboard. The deploy page shows build output, and the
  Logs view shows runtime output.

## 4. Set the health check path

`render.yaml` sets `healthCheckPath: /healthz`, but Render applies that only when a service is
created from the Blueprint. This service was created through the API, so set it by hand:

1. Open the service in the Render dashboard and go to **Settings**.
2. Set **Health Check Path** to `/healthz`.
3. Save. `/healthz` is public and returns JSON with `"status": "ok"` and `"db": "ok"`.

## 5. Rotate the password or the session secret

1. Open the service's **Environment** tab.
2. Edit `QLURE_DASHBOARD_PASSWORD` (the password) or `QLURE_DASHBOARD_SECRET` (the session secret)
   and enter the new value.
3. Save, then trigger a redeploy so the new value is used.

Sessions are signed with `QLURE_DASHBOARD_SECRET`. Changing the secret logs everyone out. Changing
only the password does not end sessions that are already open; they expire after 8 hours.

## 6. Free-plan limits

- The service **sleeps after about 15 minutes without traffic**. The first request after that takes
  **about a minute** to wake it.
- The free plan has a **limited number of build minutes**. Every push rebuilds the service, so
  frequent pushes use them up.
- The free plan has **no persistent disk**. Files written while the service runs (for example a
  settings change) are lost on the next restart or deploy. The sample data is rebuilt each time.

## 7. Take it down, or recreate it

**Take it down** in the Render dashboard, on the service's **Settings** page:

- **Suspend** stops the service and keeps its configuration. Resume it later from the same page.
- **Delete** removes the service.

**Recreate it from `render.yaml`:**

1. If the old `qlure-demo` service still exists, delete it first. Service names must be unique.
2. In the Render dashboard, choose **New > Blueprint**.
3. Connect the GitHub repository `itzz-inbathamizhanS/QLure`, branch `main`, and select the
   `render.yaml` file it finds.
4. Review the service (`qlure-demo`, free plan, Oregon) and apply it. Render creates the two
   generated secrets.
5. Open the new service's **Environment** tab to read `QLURE_DASHBOARD_PASSWORD`.
6. Wait for the first build to finish, then confirm **Health Check Path** is `/healthz` under
   **Settings** (section 4).

## 8. Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| Build fails on the Python version | `PYTHON_VERSION` is not a 3.12 release Render can install | Set `PYTHON_VERSION` in the Environment tab to a 3.12.x release (render.yaml pins 3.12.11), then redeploy |
| Login page says "Wrong password." | The typed password does not match `QLURE_DASHBOARD_PASSWORD` | Copy the value from the Environment tab, or rotate it (section 5) |
| Page is blank or slow after a quiet period | The service was asleep | Wait about a minute for it to wake, then reload |
| Signed in on http, but the cookie is not kept | `QLURE_COOKIE_SECURE=1` marks the cookie `Secure`, and browsers do not store `Secure` cookies over http | Use the https:// address. `QLURE_COOKIE_SECURE` only works on https |

## 9. The Vercel project

The earlier hosted snapshot on Vercel is a separate project. This Render service does not change it.
