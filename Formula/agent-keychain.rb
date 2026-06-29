class AgentKeychain < Formula
  desc "Project-scoped credential and browser-session isolation for local AI agents"
  homepage "https://github.com/brynary/agent-keychain"
  url "ssh://git@github.com/brynary/agent-keychain.git",
      tag:      "v0.2.0",
      revision: "a2e02c30b678dfde4662c87fb600390268011aac"
  license :cannot_represent
  head "ssh://git@github.com/brynary/agent-keychain.git", branch: "main"

  depends_on macos: :sonoma

  def install
    system "swift", "build", "-c", "release", "--disable-sandbox", "--product", "agent-keychain"
    bin.install ".build/release/agent-keychain"
  end

  test do
    assert_match "agent-keychain", shell_output("#{bin}/agent-keychain 2>&1", 2)
  end
end
