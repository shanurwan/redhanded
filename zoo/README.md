# The Zoo

Labelled samples for the eval gate. Each folder is a small npm package plus an
`expect.json` giving the verdict it is owed:

- `min_verdict`: a sample RedHanded must catch, at this severity or higher.
- `max_verdict`: a benign control that must not be flagged above this.
- `deadline_s`: optional per-sample deadline.

Every sample is harmless by construction. Samples only touch the fake bait a
scan plants, only name hosts under the reserved `.invalid` TLD, are
`"private": true`, and are never published to npm.

Run one sample: `redhanded scan zoo/<name>`. Run the gate: `redhanded eval`.
