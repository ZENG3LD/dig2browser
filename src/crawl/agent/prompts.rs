use super::protocol::SiteMemorySnapshot;
use serde_json::Value;
use std::path::Path;

// ── Phase 1: Discovery prompt ─────────────────────────────────────────────────

/// Build a Phase 1 (discovery) prompt for [`super::session::AgentSession`].
///
/// The agent reads the HTML file at `html_path` using its Read tool,
/// analyses the DOM, and returns the JSON response directly as its text
/// output (no file write).
///
/// The caller collects the agent's text response and parses JSON from it.
///
/// `spa_json_path` — if Some, points to a temp file containing extracted SPA
/// JSON (e.g. from `__NEXT_DATA__`). The prompt instructs the agent to
/// prefer JSON path extraction over CSS selectors in that case.
///
/// `spa_source_name` — display name of the SPA source (e.g. `"__NEXT_DATA__"`).
pub fn build_discovery_prompt(
    html_path: &Path,
    goal: &str,
    spa_json_path: Option<&Path>,
    spa_source_name: Option<&str>,
) -> String {
    let spa_section = match (spa_json_path, spa_source_name) {
        (Some(json_path), Some(source)) => format!(
            r#"

## IMPORTANT: This page contains embedded SPA JSON data

The page contains embedded JSON data from a SPA framework (`{source}`).
The extracted JSON has been saved to: {json_path}

**Read this JSON file** (using the Read tool) to find the pricing/product data.
Look for arrays of objects whose field names match the goal.

If you find the target data in the JSON, return `"extraction_mode": "json_path"` in your response
with `"json_source": "{source}"` and `"json_base_path": "<dot.path.to.array>"`.
In that case you do NOT need CSS selectors — set `"container_selector": ""` and leave `"field_configs"` empty.

Example for json_path mode:
```json
{{
  "extraction_mode": "json_path",
  "json_source": "{source}",
  "json_base_path": "props.pageProps.plans"
}}
```
"#,
            json_path = json_path.display(),
            source = source,
        ),
        _ => String::new(),
    };

    let nav_section = if spa_json_path.is_none() {
        r#"

## Auto-navigation

IMPORTANT: If this page does NOT contain the data described in the goal (e.g. it is a homepage,
landing page, or marketing page without actual pricing/plan listings), then:

1. Look for navigation links, menu items, or buttons that would lead to the actual data page.
2. Return a JSON response with:
   ```json
   {{"status": "navigate", "target_url": "https://...", "reason": "Current page is homepage, pricing data is at /pricing"}}
   ```
The crawler will fetch that URL and re-run discovery on it.
Only navigate if you are confident the current page does not contain the goal data.
"#
    } else {
        ""
    };

    format!(
        r#"You are a CSS selector discovery agent. Your task is to analyse HTML and find precise selectors for structured data extraction.

## Goal
{goal}
{spa_section}{nav_section}
## Instructions

1. Use the Read tool to read the HTML file at: {html_path}
   **IMPORTANT**: The file may be large. If you get a "File content exceeds maximum allowed tokens" error, use `offset` and `limit` parameters to read the file in chunks (e.g. offset=1, limit=2000, then offset=2001, limit=2000, etc.). Read until you find the section with repeating data items. Use Grep on the file to quickly locate relevant sections (e.g. search for "price", "plan", "tariff", or class names related to the goal).
2. Analyse the DOM structure — look for repeating elements, JSON-LD, data attributes, class patterns.
3. Find the CSS selector for the **repeating container** element that wraps each individual item (e.g. a product card, a job listing, an article summary).
4. For each requested field, find the CSS selector **relative to the container** and determine the best extraction mode.
5. Identify the pagination pattern if one exists.

## Response format

Return ONLY a single valid JSON object as your response text — no prose, no markdown code blocks, no explanation:

```json
{{
  "version": "2.0.0",
  "task_id": "discovery",
  "status": "success",
  "records": [],
  "next_urls": [],
  "confidence": 0.85,
  "logs": ["<brief note about what you found>"],
  "field_configs": [
    {{
      "name": "<field name from goal>",
      "selector": "<CSS selector relative to container>",
      "extract": "text",
      "prefix": null,
      "transform": null
    }}
  ],
  "updated_memory": {{
    "domain": "<domain>",
    "selectors": {{
      "listing": {{
        "container_selector": "<container CSS selector>",
        "fields": {{}},
        "confidence": 0.85,
        "validated_on_pages": 0
      }}
    }},
    "url_patterns": {{}},
    "pages_seen": 1,
    "records_found": 0,
    "requires_browser": false,
    "notes": []
  }},
  "pagination": {{
    "type": "next_button",
    "selector": "a.next-page"
  }}
}}
```

### `extract` values
- `"text"` — element.textContent trimmed
- `{{"attribute": "href"}}` — element.getAttribute("href")
- `"html"` — element.innerHTML
- `"outer_html"` — element.outerHTML

### `transform` values (optional, null if not needed)
- `"trim"` — trim whitespace
- `"lowercase"` / `"uppercase"`
- `{{"regex": "pattern"}}` — return capture group 1
- `{{"replace": ["from", "to"]}}`
- `"parse_number"`

### `pagination` type values
- `{{"type": "next_button", "selector": "..."}}` — a "Next" link/button
- `{{"type": "url_pattern", "template": "https://site.com/page/{{n}}", "start": 1, "end": null, "step": 1}}`
- `{{"type": "infinite_scroll", "trigger_px": 200, "max_scrolls": 20}}`
- `{{"type": "load_more", "button_selector": "...", "max_clicks": 10}}`
- `{{"type": "offset_param", "param_name": "offset", "page_size": 20, "max_pages": null}}`
- omit the `"pagination"` key entirely if there is no pagination

## Rules
- Read the HTML file first — do NOT rely on memory or guesses.
- Container selector must match ALL items on the page, not just one.
- Field selectors must be relative to the container element.
- Only include fields that are present in the HTML. Use confidence 0.0 for fields you could not find.
- Do not hallucinate selectors. If unsure, set a lower confidence value.
- Output exactly one JSON object. Do NOT wrap it in markdown fences."#,
        html_path = html_path.display(),
        goal = goal,
        spa_section = spa_section,
        nav_section = nav_section,
    )
}

// ── Phase 2: Validation prompt ────────────────────────────────────────────────

/// Build a Phase 2 (validation) prompt for [`super::session::AgentSession`].
///
/// Asks the agent to verify whether the [`SiteMemorySnapshot`] selectors
/// discovered in Phase 1 actually match the provided sample data. Returns a
/// `validation_result` block inside the standard [`super::protocol::AgentResponse`]
/// JSON as direct text output.
///
/// `extracted_data` is a slice of JSON values produced by the fast-path selector
/// extractor. The prompt shows the agent this data so it can cross-check field
/// coverage and value quality without re-reading the full HTML.
pub fn build_validation_prompt(extracted_data: &[Value], profile: &SiteMemorySnapshot) -> String {
    let data_json = serde_json::to_string_pretty(extracted_data).unwrap_or_else(|_| "[]".to_string());
    let profile_json = serde_json::to_string_pretty(profile).unwrap_or_else(|_| "{}".to_string());

    format!(
        r#"You are a data quality validation agent. Your task is to verify whether CSS-selector-based extraction produced correct, complete results.

## Site profile (selectors that were used)
```json
{profile_json}
```

## Extracted data (sample — up to 10 items)
```json
{data_json}
```

## Your task

Review the extracted data against the site profile and answer:
1. Did the container selector match items correctly (no empty or garbage records)?
2. For each field, does the extracted value look correct and complete?
3. Are there any systematic errors (wrong selector, missing data, garbled text)?
4. What is your overall confidence that this config will work on future pages?

## Response format

Return ONLY a single valid JSON object as your response text — no prose, no markdown code blocks:

```json
{{
  "version": "2.0.0",
  "task_id": "validation",
  "status": "success",
  "records": [],
  "next_urls": [],
  "confidence": 0.9,
  "logs": [],
  "validation_result": {{
    "passed": true,
    "items_extracted": 8,
    "field_status": {{
      "title": true,
      "price": true,
      "url": false
    }},
    "summary": "Container selector matched 8 items. Title and price fields extracted correctly. URL field returned relative paths — prefix needed.",
    "confidence": 0.87,
    "issues": [
      "url field: values are relative (/product/123), need domain prefix"
    ]
  }}
}}
```

## Rules
- `passed` is true only if the majority of fields extracted meaningful non-empty values.
- `items_extracted` is the count of non-empty records in the sample data.
- `field_status` must have an entry for every field present in the site profile.
- `issues` lists actionable problems — empty array if everything is fine.
- `confidence` reflects how likely this config is to work on unseen pages of the same site.
- Output exactly one JSON object. Do NOT wrap it in markdown fences."#
    )
}

// ── Level 2: Interactive prompt ───────────────────────────────────────────────

/// Build a Level 2 (interactive) prompt for the agent.
///
/// Tells the agent that L1 CSS extraction found insufficient data and asks
/// it to return `browser_actions` — a list of interactions to expose hidden
/// content. The agent reads the HTML file via its Read tool and returns JSON
/// as direct text.
pub fn build_interactive_prompt(
    html_path: &std::path::Path,
    goal: &str,
    l1_failure_reason: &str,
) -> String {
    format!(r#"# Level 2: Interactive Extraction

## Context
You previously analyzed a page for CSS selectors (Level 1), but the extraction was insufficient: {l1_failure_reason}.

The page may require user interactions to reveal data — e.g. clicking "Load More" buttons, dismissing cookie consent banners, expanding collapsed sections, or filling search forms.

## Your Task
1. Read the HTML file at: {html_path}
2. Identify what browser interactions would expose more data relevant to the goal
3. Return a JSON response with `browser_actions` array AND any CSS `field_configs` you can already determine

## Goal
{goal}

## Browser Actions You Can Return
Each action is a JSON object with a `type` field:
- `{{"type": "click", "selector": "CSS selector"}}` — click an element
- `{{"type": "type", "selector": "CSS selector", "text": "text to type"}}` — type into an input
- `{{"type": "scroll_bottom"}}` — scroll to page bottom (for infinite scroll)
- `{{"type": "scroll_to", "selector": "CSS selector"}}` — scroll element into view
- `{{"type": "wait_for_element", "selector": "CSS selector", "timeout_ms": 5000}}` — wait for element
- `{{"type": "wait_ms", "ms": 2000}}` — wait fixed time (max 10s)
- `{{"type": "dismiss_overlay", "selector": "CSS selector"}}` — dismiss cookie/GDPR banner
- `{{"type": "press_key", "key": "Enter"}}` — press keyboard key
- `{{"type": "select_option", "selector": "CSS selector", "value": "option value"}}` — select dropdown

## Rules
- Return at most 5 actions per response
- Prefer `dismiss_overlay` FIRST if cookie/GDPR banners are detected
- Only return actions you are confident about — false positives waste time
- If the page is already fully loaded and CSS selectors should work, return empty `browser_actions` and improve your `field_configs` instead
- Set `needs_visual_pass: true` if you suspect the page uses dynamic class names or canvas rendering

## Response Format

Return ONLY a single valid JSON object as your response text — no prose, no markdown code blocks:

```json
{{
  "version": "2.0.0",
  "task_id": "interactive",
  "status": "success",
  "records": [],
  "next_urls": [],
  "browser_actions": [...],
  "needs_visual_pass": false,
  "field_configs": [...],
  "confidence": 0.7,
  "logs": []
}}
```

Do NOT wrap in markdown fences. Output exactly one JSON object."#,
        html_path = html_path.display(),
        goal = goal,
        l1_failure_reason = l1_failure_reason,
    )
}

// ── Level 2: Post-action re-extraction prompt ─────────────────────────────────

/// Build a Level 2 re-extraction prompt after browser actions were executed.
///
/// The agent receives the updated HTML (post-actions) via Read tool and
/// re-runs CSS selector discovery. Returns JSON as direct text output.
pub fn build_post_action_prompt(
    post_action_html_path: &std::path::Path,
    goal: &str,
    executed_actions_json: &str,
) -> String {
    format!(r#"# Level 2: Post-Action Re-Extraction

## Context
Browser actions were executed on the page. Here is what was done:
```json
{executed_actions_json}
```

The page HTML has been re-captured after these actions.

## Your Task
1. Read the updated HTML file at: {post_action_html_path}
2. Find CSS selectors for the data specified in the goal
3. Return standard AgentResponse with `field_configs`

## Goal
{goal}

## Response Format

Return ONLY a single valid JSON object as your response text — no prose, no markdown code blocks:

```json
{{
  "version": "2.0.0",
  "task_id": "post_action",
  "status": "success",
  "records": [],
  "next_urls": [],
  "field_configs": [...],
  "confidence": 0.8,
  "browser_actions": [],
  "logs": []
}}
```

Do NOT return more browser_actions unless absolutely necessary. This is a re-extraction pass — focus on finding selectors in the updated DOM.
Do NOT wrap in markdown fences. Output exactly one JSON object."#,
        post_action_html_path = post_action_html_path.display(),
        goal = goal,
        executed_actions_json = executed_actions_json,
    )
}

// ── Level 3: Visual prompt ────────────────────────────────────────────────────

/// Build a Level 3 (visual) prompt for the agent's vision turn.
///
/// The agent reads a screenshot PNG and identifies interactive elements by
/// appearance. Returns JSON as direct text output (no file write).
pub fn build_visual_prompt(screenshot_path: &std::path::Path, goal: &str, html_hint: &str) -> String {
    let html_context = if html_hint.is_empty() {
        String::new()
    } else {
        format!(
            "\n## HTML Hint (may be incomplete)\n```html\n{}\n```\n",
            &html_hint[..html_hint.len().min(2000)]
        )
    };

    format!(r#"# Level 3: Visual Extraction

## Context
CSS selectors (Level 1) and browser interactions (Level 2) both failed to extract sufficient data. You now have a screenshot of the page to work with.

## Your Task
1. Read the screenshot at: {screenshot_path}
2. Describe what you see on the page (layout, visible data, buttons, forms)
3. Identify any interactive elements that could reveal data (buttons, expandable sections, tabs)
4. Return `visual_actions` with coordinates of elements to interact with
{html_context}
## Goal
{goal}

## Visual Actions You Can Return
Each action is a JSON object with an `action` field:
- `{{"action": "click", "x": 150.0, "y": 300.0, "description": "Load More button at bottom"}}` — click at coordinates
- `{{"action": "type", "x": 50.0, "y": 100.0, "text": "search query", "description": "search input field"}}` — type at coordinates
- `{{"action": "scroll", "delta_y": 500, "description": "scroll down to see more content"}}` — scroll
- `{{"action": "no_action", "reason": "page content is fully visible, no interactions needed"}}` — nothing to do

Coordinates are viewport-relative pixels (top-left is 0,0).

## Response Format

Return ONLY a single valid JSON object as your response text — no prose, no markdown code blocks:

```json
{{
  "version": "2.0.0",
  "task_id": "visual",
  "status": "success",
  "records": [],
  "next_urls": [],
  "visual_actions": [...],
  "field_configs": [...],
  "confidence": 0.5,
  "logs": []
}}
```

Do NOT wrap in markdown fences. Output exactly one JSON object."#,
        screenshot_path = screenshot_path.display(),
        goal = goal,
        html_context = html_context,
    )
}
