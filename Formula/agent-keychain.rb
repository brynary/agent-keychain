class AgentKeychain < Formula
  desc "Project-scoped credential and browser-session isolation for local AI agents"
  homepage "https://github.com/brynary/agent-keychain"
  version "0.6.0"

  if Hardware::CPU.arm?
    url "https://github.com/brynary/agent-keychain/releases/download/v0.6.0/agent-keychain-0.6.0-macos-arm64.tar.gz"
    sha256 "aefd4eeb7978c58a0fa59077b93259ad341c6422cd218b50bf4690f90660eda0"
  else
    url "https://github.com/brynary/agent-keychain/releases/download/v0.6.0/agent-keychain-0.6.0-macos-x86_64.tar.gz"
    sha256 "0802f78be8f7fcd67d0c764abea7fdb5c1c5cf44674e1c7c22a794c804290193"
  end

  license "MIT"
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
