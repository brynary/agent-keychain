class AgentKeychain < Formula
  desc "Project-scoped credential and browser-session isolation for local AI agents"
  homepage "https://github.com/brynary/agent-keychain"
  version "0.4.0"

  if Hardware::CPU.arm?
    url "https://github.com/brynary/agent-keychain/releases/download/v0.4.0/agent-keychain-0.4.0-macos-arm64.tar.gz"
    sha256 "8257b664494f7bde5ec85f4dd2df0bd056973cd9a10aa06c8512d28401141104"
  else
    url "https://github.com/brynary/agent-keychain/releases/download/v0.4.0/agent-keychain-0.4.0-macos-x86_64.tar.gz"
    sha256 "994e4c42d39045cb6c2082e008d4a4456532b969c3e08ec5288f6e110a25e2cd"
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
