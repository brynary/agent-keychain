class AgentKeychain < Formula
  desc "Project-scoped credential and browser-session isolation for local AI agents"
  homepage "https://github.com/brynary/agent-keychain"
  url "ssh://git@github.com/brynary/agent-keychain.git",
      tag:      "v0.1.0",
      revision: "290264571965950c3598a855510df17d7934416c"
  license :cannot_represent
  head "ssh://git@github.com/brynary/agent-keychain.git", branch: "main"

  depends_on macos: :sonoma

  def install
    system "swift", "build", "-c", "release", "--disable-sandbox", "--product", "agent-keychain"
    bin.install ".build/release/agent-keychain"
  end

  test do
    assert_match "Usage: agent-keychain <command>", shell_output("#{bin}/agent-keychain 2>&1", 2)
  end
end
