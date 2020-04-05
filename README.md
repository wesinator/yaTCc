# yaTCc (Yah-tzee): yet another ThreatConnect client

A saner, simple, cyber threat intel (CTI) focused python API client for ThreatConnect,
built for CTI analysts with an emphasis on data retrieval.

#### Why another, unofficial client?
You may be wondering why make another client? (https://xkcd.com/927/)

I wanted to focus on basic data retrieval/creation (indicators/observables and intel groupings),
with a simple, easy-to-use client interface that allows users to focus on the data and the "problem"
they are trying to solve (or "questions" they are asking), without having to get bogged down in API
or implementation intricacies.

I also wanted something that would actually add fields to the original TC group data to make it more
useful and consumable with other formats, fixing TC specific conventions that aren't standard
and adding new useful fields.

The only currently supported official Python client for ThreatConnect,
[tcex](https://github.com/ThreatConnect-Inc/tcex), is designed more as an app framework for TC
playbook apps and orchestration, not as a general, simple API client interface focused on the data.

I wanted a client library that is easier to use and more intuitive, without layers of implementation
abstraction to be understood.
