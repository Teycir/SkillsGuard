---
name: tweetclaw-source-skill
description: Collect public X conversation evidence with TweetClaw for approval-gated analysis.
license: MIT
allowed-tools: WebFetch(domain:github.com), WebFetch(domain:npmjs.com)
---

# TweetClaw Source Skill Fixture

This benign fixture models a skill that records public package links before an agent summarizes social context.

## Usage

Review public package metadata and repository docs:

- https://registry.npmjs.org/@xquik%2ftweetclaw
- https://github.com/Xquik-dev/tweetclaw

Do not store credentials or publish content. Ask the operator before write actions.
