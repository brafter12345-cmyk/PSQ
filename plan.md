# CRM Build-Out Plan — Phase 1

## What We're Building
Fix existing bugs, add activity logging, notes, search, archive/delete, and invoice status flow.

## 1. Fix Bugs (4 issues)

- **client_list.html**: Route passes `stage` but template expects `active_stage`; query aliases `primary_contact` but template expects `contact_name`; `last_scan` not in query
- **renewals.html**: `active_days` not passed from route; `days_left` not computed
- **dashboard.html**: `days_left` and `days_overdue` not computed in route
- **Invoice status**: Only draft→paid exists; no "sent" or "overdue" states

## 2. New DB Tables

```sql
-- Activity log (auto-logged on every mutation)
CREATE TABLE IF NOT EXISTS activities (
    id TEXT PRIMARY KEY,
    entity_type TEXT NOT NULL,  -- client/quote/invoice/policy/scan/payment
    entity_id TEXT NOT NULL,
    client_id TEXT DEFAULT '',
    action TEXT NOT NULL,
    detail TEXT DEFAULT '',
    created_at TEXT NOT NULL
);

-- Client notes
CREATE TABLE IF NOT EXISTS client_notes (
    id TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    text TEXT NOT NULL,
    created_at TEXT NOT NULL
);

-- Soft-delete column added to clients, quotes, invoices
ALTER TABLE clients ADD COLUMN archived INTEGER DEFAULT 0;
ALTER TABLE quotes ADD COLUMN archived INTEGER DEFAULT 0;
ALTER TABLE invoices ADD COLUMN archived INTEGER DEFAULT 0;
```

## 3. New Routes (8 total)

| Method | Route | Purpose |
|--------|-------|---------|
| POST | `/crm/clients/<id>/notes` | Add note to client |
| POST | `/crm/clients/<id>/notes/<nid>/delete` | Delete a note |
| GET | `/crm/search?q=` | Global search (clients, policies, invoices) |
| POST | `/crm/invoices/<id>/send` | Mark invoice as sent |
| POST | `/crm/clients/<id>/archive` | Archive client |
| POST | `/crm/clients/<id>/unarchive` | Unarchive client |
| POST | `/crm/quotes/<id>/archive` | Archive quote |
| POST | `/crm/invoices/<id>/archive` | Archive invoice |

## 4. New Helpers

- `log_activity(entity_type, entity_id, client_id, action, detail)` — insert into activities table
- `auto_update_invoice_statuses()` — mark sent invoices as overdue if past due_date

## 5. Activity Logging Points

Every mutation route gets a `log_activity()` call:
- create/update client, create/accept/decline quote, bind quote, create invoice, record payment, link scan, renew policy, send invoice, archive/unarchive

## 6. Template Changes

- **_base_crm.html**: Add search input in sidebar, CSS for `.sent` and `.archived` pills
- **client_detail.html**: Add Notes card, Activity Timeline card, Archive/Unarchive button
- **client_list.html**: Add "Archived" filter tab
- **invoice_detail.html**: Add "Mark as Sent" button, Archive button
- **NEW search_results.html**: Search results with clients/policies/invoices sections

## 7. Files Modified

- `security_scanner/app.py` — bug fixes, new tables, new routes, activity logging (~180 new lines)
- `security_scanner/templates/crm/_base_crm.html` — search bar, new CSS
- `security_scanner/templates/crm/client_detail.html` — notes, activity, archive
- `security_scanner/templates/crm/client_list.html` — archived tab
- `security_scanner/templates/crm/invoice_detail.html` — sent/archive buttons
- `security_scanner/templates/crm/search_results.html` — NEW

## Execution

Two parallel agents:
1. **Agent A**: All `app.py` changes (bugs, tables, helpers, routes)
2. **Agent B**: All template changes (6 files)

Then verify with dev server and push to master.
