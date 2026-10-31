# Newcomer test

The runner shows that the libraries work together when someone who knows them
wires them up. The newcomer test asks a different question: can a developer who
has never seen aauth-rust or aauth-go build a working agent and API from the
libraries' documentation alone?

Run it by hand. The procedure stays the same from run to run, so records from
different runs can be compared.

## Who tests

One tester per run: a person, or an agent from a vendor whose agents have not
worked on either library or on this project. The tester has not read either
library's source. Record who tested and what they knew of AAuth
beforehand.

## What the tester gets

- The two targets: an aauth-rust tag and an aauth-go commit, for example
  `v0.1.0-alpha.17` and `0e2447b`.
- An empty directory outside any checkout of the libraries or of this project.
- Network access to the package sources: gitlab.com, crates.io and the Go
  module proxy.

The tester may read, in each library's repository at the target revision: the
Markdown files (README.md, USE-IN-YOUR-SERVICE.md and the rest), the examples,
and the generated API documentation (`cargo doc`, `go doc`). The tester may read
the AAuth drafts. The tester does not read this project, the libraries' tests or
their non-example source, and gets no help from anyone who worked on them. If
the tester has to read library source to make progress, they record the file and
the reason: that is a documentation gap.

The tester's code depends on the libraries the way an outside project does:
Rust through a git dependency on the tag
(`git = "https://gitlab.com/sidecat-dev/aauth-rust.git", tag = "..."`), Go
through `go get gitlab.com/sidecat-dev/aauth-go@COMMIT`. Copying an example
into the new project and changing it is allowed; record which example.

## Tasks

Give the tester the tasks in this order. Each task builds something new in the
tester's own directory.

1. **Rust API and agent.** An Agent Provider that issues an agent token, an
   agent that holds it, and an API with one protected endpoint, `GET /hello`.
   The API decides on the agent's identity alone. A request without an agent
   token gets `401` with `AAuth-Requirement: requirement=agent-token`
   (protocol draft, `draft-hardt-oauth-aauth-protocol.md` lines 562-566 at
   [`70d6737`](https://github.com/dickhardt/AAuth/blob/70d67375deb0bb002af7da0711fc58f6e8926e7e/draft-hardt-oauth-aauth-protocol.md#L562-L566)).
   A signed request from the agent gets `200` and a body naming the agent
   identifier the API verified.
2. **Go API and agent.** The same three parts with aauth-go.
3. **Across languages.** The Rust agent calls the Go API, and the Go agent
   calls the Rust API. The API trusts the other language's Agent Provider.
4. **Optional: authorization.** The Rust API requires an auth token from a
   Person Server the tester runs, and the Rust agent obtains one and calls it.
   Record the challenge the API sends and the statuses on the way.

Ports, transport and key storage are the tester's choice: loopback, plain HTTP
or HTTPS with a self-signed certificate, in-memory keys.

## The interface `newcomer/check.sh` expects

- **API:** listens on a URL the tester chooses and serves `GET /hello`.
- **Agent:** a command that takes the URL as its last argument, makes one
  signed `GET`, and prints the HTTP status on the first line of its output,
  then the body.

For each agent and API pair, run from this repository:

```sh
newcomer/check.sh --url https://127.0.0.1:8443/hello --agent '/path/to/rust-agent'
```

Add `--cacert FILE` if the API uses a certificate curl should verify. The
script prints one line per check (`unsigned` must be `401` with an
`AAuth-Requirement` header; `signed` must be `200`) and exits 0 only when both
pass. Run it for the four pairs: Rust agent and Rust API, Go agent and Go API,
Rust agent and Go API, Go agent and Rust API.

## The measure

For each task, one outcome:

- **from the docs:** finished using only the allowed material;
- **with a gap:** finished, but only after reading library source, guessing, or
  working around something the docs got wrong;
- **not finished:** stopped, with the point where it stopped.

Plus, for the run: the `check.sh` output for each pair, and the list of
documentation gaps, each with the document and section where the tester looked
and what was missing or wrong.

## Keep the record

Copy [newcomer/RECORD-TEMPLATE.md](newcomer/RECORD-TEMPLATE.md) to where your
QA records live, fill it in, and keep the tester's code next to it. Records do
not go in this repository. Report each documentation gap to the library it
concerns.

## Repeat it

Run the test again for each new release of either library, with a new tester
each time. Same tasks, same template, same allowed material. Compare the gap
lists: a gap closed by a release, and a gap that appeared, are both findings.
