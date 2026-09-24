# Ramadan API Console (UI)

A single static page that talks to the deployed API at
`https://ramadan-rmhl.onrender.com`. No build step, no dependencies.

## Run locally

Open `index.html` in a browser, or serve the folder:

```sh
npx serve docs
```

## Deploy to GitHub Pages

1. Push this folder to `main`.
2. **Settings → Pages → Build and deployment**
   - Source: *Deploy from a branch*
   - Branch: `main`, folder: `/docs`
3. The page appears at `https://<user>.github.io/<repo>/`.

To point at a different backend, change the `API` constant at the top of the
`<script>` block in `index.html`.

## Notes

- The token is a 1-hour JWT kept in `localStorage`; the UI returns you to the
  login screen when the API answers `401`.
- The backend sleeps when idle, so the first request can take up to a minute.
- Admin endpoints are scoped to the caller's tenant and answer `403` for
  regular users.
