class AgentKeychain < Formula
  desc "Project-scoped credential and browser-session isolation for local AI agents"
  homepage "https://github.com/brynary/agent-keychain"
  version "0.8.0"

  if Hardware::CPU.arm?
    url "https://github.com/brynary/agent-keychain/releases/download/v0.8.0/agent-keychain-0.8.0-macos-arm64.tar.gz"
    sha256 "f9b452d2e3738b8f05982fafe6ae9f914b9ae8b7744fe38f74646c09a5b9f46d"
  else
    url "https://github.com/brynary/agent-keychain/releases/download/v0.8.0/agent-keychain-0.8.0-macos-x86_64.tar.gz"
    sha256 "1fe6a795792c727a12b26b560657957ed2598ea074bccd8da71eea5ae62bb3d8"
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
