class AgentKeychain < Formula
  desc "Project-scoped credential and browser-session isolation for local AI agents"
  homepage "https://github.com/brynary/agent-keychain"
  version "0.3.0"

  if Hardware::CPU.arm?
    url "https://github.com/brynary/agent-keychain/releases/download/v0.3.0/agent-keychain-0.3.0-macos-arm64.tar.gz"
    sha256 "69bbf704d88771d2c95b2b2d23bd13be38242e83b8ee12b9a4f96c9be5f59be2"
  else
    url "ssh://git@github.com/brynary/agent-keychain.git",
        tag:      "v0.3.0",
        revision: "5d35722da61300ad020223cff33ca6ade92cf48e"
  end

  license :cannot_represent
  head "ssh://git@github.com/brynary/agent-keychain.git", branch: "main"

  depends_on macos: :sonoma

  def install
    release_binary = File.exist?("agent-keychain") ? "agent-keychain" : Dir["*/agent-keychain"].first

    if build.head? || release_binary.nil?
      system "swift", "build", "-c", "release", "--disable-sandbox", "--product", "agent-keychain"
      bin.install ".build/release/agent-keychain"
    else
      bin.install release_binary => "agent-keychain"
    end
  end

  test do
    assert_match "agent-keychain", shell_output("#{bin}/agent-keychain 2>&1", 2)
  end
end
