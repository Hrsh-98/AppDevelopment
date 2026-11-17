# School Portal

Run with Node.js 20+:

```sh
npm start
```

Open `http://localhost:3000`. On first launch, the server creates `data/school.json` and a seeded administrator account:

- Email: `admin@school.local`
- Password: `ChangeMe!2026`

Change the seeded password before using this outside development. The API authenticates with signed, HTTP-only cookies and enforces roles on every protected route. Data is kept in a local JSON store so the starter has no external dependency; replace `Store` in `server.js` with a database adapter for production.
