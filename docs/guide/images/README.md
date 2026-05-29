# Screenshot images for USER_GUIDE.md

Drop your PNG screenshots in this directory with the exact filenames below. Both `USER_GUIDE.md` (rendered on GitHub) and the regenerated `USER_GUIDE.docx` will pick them up automatically.

## Expected images

| # | Filename | Status | What to capture |
|---|---|---|---|
| 1 | `01-homepage.png` | **TODO** | `https://idp.<yourdomain>/` — the simulator homepage with the "Identity Provider Made Simple" hero |
| 2 | `02-dokploy-env-tab.png` | ✅ Present | Dokploy → your app → Environment tab showing `ENABLE_SCIM=true` |
| 3 | `03-bootstrap-token-banner.png` | **TODO** | `/admin/scim/` SCIM Dashboard with the yellow bootstrap-token banner |
| 4 | `04-cp-idp-list.png` | **TODO** | Check Point SASE → Settings → Identity Providers page (before adding Entra) |
| 5 | `05-cp-idp-picker.png` | ✅ Present | The "Add identity provider" modal with Microsoft Entra ID highlighted |
| 6 | `06-cp-entra-form.png` | ✅ Present | The Microsoft Entra ID form filled with dummy values and **SCIM Integration** checked |
| 7 | `07-cp-idp-added.png` | ✅ Present | Identity Providers page after adding Entra — "SCIM Integration: On" visible |
| 8 | `08-cp-scim-settings.png` | ✅ Present | The SCIM Settings panel with Tenant URL + "Generate Token" button |
| 9 | `09-sim-scim-nav.png` | ✅ Present | Simulator admin nav with the SCIM dropdown open |
| 10 | `10-sim-add-target.png` | **TODO** | The Add SCIM Target form with the US region preset clicked |
| 11 | `11-sim-sync-success.png` | ✅ Present | Outbound Targets page with the green "Sync to ...: N created, N updated, 0 errored" banner |
| 12 | `12-sim-push-log.png` | ✅ Present | SCIM Push Log table showing CREATE_USER / FIND_USER / PATCH_USER rows |
| 13 | `13-cp-members-synced.png` | ✅ Present | Check Point SASE → Team → Members showing the synced users with Identity Provider = Entra ID |

## After dropping images in

Run the regeneration helper from the project root:

```bash
./docs/build_user_guide.sh
```

This re-runs pandoc to bake the images into `docs/USER_GUIDE.docx`. Commit both the images and the regenerated docx.

If you only update one image, just rerun the script — it always regenerates from `USER_GUIDE.md` so the markdown is the single source of truth.

## File-size guidance

- Crop tightly to the relevant UI area (avoid full-screen captures that have lots of empty space)
- Use PNG, keep each image under ~500 KB
- Width 1200-1600px is plenty for the docx; pandoc will scale to page width
