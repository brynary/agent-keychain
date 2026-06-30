class AgentKeychain < Formula
  desc "Project-scoped credential and browser-session isolation for local AI agents"
  homepage "https://github.com/brynary/agent-keychain"
  version "0.7.1"

  if Hardware::CPU.arm?
    url "https://github.com/brynary/agent-keychain/releases/download/v0.7.1/agent-keychain-0.7.1-macos-arm64.tar.gz"
    sha256 "9fd3e5482da7d39de00230fc5561c68bd63d29c3d5e5858d1906e9e2d9e1e60a"
  else
    url "https://github.com/brynary/agent-keychain/releases/download/v0.7.1/agent-keychain-0.7.1-macos-x86_64.tar.gz"
    sha256 "362c97f551c3bf98dc1422c4940f8ccebc2d244b6db037431b086bec1dc06e01"
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
