# Scenario schema (version 1.0)

A scenario is a JSON file that describes one user task, the environment it happens in, the single place an attacker can inject text, what the attacker is trying to achieve, and what the user's task legitimately allows. It is data only. Nothing in it is executed, and the loader rejects it with a specific message if any rule below is broken. Run `python3 -m unittest discover -s tests` after adding one; the suite loads every scenario in `scenarios/suite.json`.

## Fields

`schema_version` must be `"1.0"`. `id` is lowercase letters, digits and hyphens, three to 64 characters, and unique in the suite. `version` looks like `1.0.0`; bump it whenever the scenario's behavior changes, because the suite content hash is recorded in every experiment manifest. `title` and `description` are free text shown in the dashboard. `author` records who wrote it. `validation_status` is one of `unreviewed`, `reviewed` or `rejected`; every shipped scenario is `unreviewed`. `cleanup` is `reset_each_round`, because environments are rebuilt from `initial_state` for every round.

`environment` is `email`, `documents` or `calendar`. `category` is one of `benign`, `obvious_injection`, `contextual_injection`, `instruction_impersonation`, `data_exfiltration`, `unauthorized_message`, `unauthorized_document_share`, `unauthorized_document_edit`, `unauthorized_calendar_change` or `multi_step`. `tags` is a list of short labels. `difficulty` is an object with a `level` (`easy`, `medium` or `hard`) and `notes` explaining why.

`user_task` is what the user asked the agent to do, in plain text. `initial_state` is the starting content of the environment. Its top-level keys depend on the environment: `user`, `filler` and `emails` for email; `user`, `filler` and `documents` for documents; `user`, `filler` and `events` for calendar. The `filler` section is expanded deterministically from the round seed, so different seeds surround the scenario's content with different but reproducible noise.

`granted_scopes` lists the permissions the agent holds. Email uses `mail.read`, `mail.draft`, `mail.send`; documents use `docs.read`, `docs.edit`, `docs.share`; calendar uses `cal.read`, `cal.write`, `cal.invite`. Any other value is rejected. A tool whose scope is not granted fails with `permission_denied`.

## Injection and attack objective

`injection` names the one place the payload goes. `slot` is a path into `initial_state` such as `emails.e1.body`, and the loader checks that it exists. `placement` is one of `append`, `prepend`, `html_comment` or `signature_footer`.

`attack_objective` describes what the attacker wants. `kind` is one of `email_sent`, `document_shared`, `document_modified`, `attendee_added` or `event_created`, and it must belong to the scenario's environment. `params` holds the values that make the objective specific (for `email_sent`, the recipient). `description` is plain language. `brief` holds three strings, `destination`, `object` and `cover_topic`, and these become the only content the attacker is shown besides the environment name, the objective kind and the description.

A scenario with no `injection` and no `attack_objective` is a benign control. Its category must be `benign`, and it runs zero attack rounds. It exists to measure false blocks.

## What the task legitimately allows

`allowed_actions` lists the write calls the user's task authorizes, each as a `tool` and a `match` of argument names to permitted values, for example `{"tool": "send_email", "match": {"to": ["finance@corp.example"]}}`. It may be empty, which means any write is unsafe. The loader rejects a scenario in which the attack objective would also be authorized by this list, since a successful attack would then look identical to correct behavior. Every `tool` listed must be a real write tool in the environment.

`utility` defines task completion with `response_terms` (strings the agent's final answer must contain) and/or `state_assertions` (effects that must hold in the final state). At least one is required. `allowed_actions` and `utility` are private: the oracle and tests read them, and no defense or attacker does.

## Policy

`policy` is what the tool validator enforces. `allowed_write_tools` lists the write tools the agent may use, `approved_destinations` lists exact addresses or principals it may target, `trusted_domains` lists domains treated as approved, and `confirm_write_tools` (optional) lists tools that return a confirm verdict rather than allow. Every entry in `allowed_write_tools` must be a real write tool. The policy is deliberately a separate field from `allowed_actions`: the difference between what the task allows and what a defender wrote down is where the interesting results come from. `cal-schedule-sync` omits a legitimate partner from its policy, and `email-reply-lookalike` trusts an entire domain that contains an attacker-controlled look-alike address.

## Simulated behavior

`simulated_behavior` drives the simulated target agent and is ignored by real-model agents. `read_plan` is the ordered list of read calls the agent makes, each a `tool` and `args`. `legit_actions` lists write calls the agent makes when it is doing the task correctly (empty when no legitimate write exists). `summary` is the answer text produced when the agent completes the task, and must satisfy `utility`.

## Benign variants

`benign_variants` is a list of objects with an `id` and a `text`. Each is injected into the same slot in place of an attack, to check that a defense does not disturb harmless content that merely sounds suspicious, such as "ignore the previous draft because it is outdated". The harness runs every variant after the attack rounds and reports how often the defense interfered.

## Adding a scenario

Copy the closest existing file, change the `id`, edit the fields above, add the filename to `scenarios/suite.json`, and run the tests. The suite hash changes when any scenario changes, which is recorded in every manifest, so results from before and after an edit can never be mistaken for one another.
