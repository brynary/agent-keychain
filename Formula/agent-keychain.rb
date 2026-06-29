class AgentKeychain < Formula
  desc "Project-scoped credential and browser-session isolation for local AI agents"
  homepage "https://github.com/brynary/agent-keychain"
  version "0.5.1"

  if Hardware::CPU.arm?
    url "https://github.com/brynary/agent-keychain/releases/download/v0.5.1/agent-keychain-0.5.1-macos-arm64.tar.gz"
    sha256 "e5edba89f255d1831ec1344d9c5ff2db2f8ffc42cbc6a5de60aaf87b4b783976"
  else
    url "https://github.com/brynary/agent-keychain/releases/download/v0.5.1/agent-keychain-0.5.1-macos-x86_64.tar.gz"
    sha256 "70dfd8b17e331917d703f693ce038480da5893bbfc828ab22cdabfbb774b3a3e"
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
