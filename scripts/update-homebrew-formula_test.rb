#!/usr/bin/env ruby
# frozen_string_literal: true

require "minitest/autorun"
require "open3"
require "tmpdir"

class UpdateHomebrewFormulaTest < Minitest::Test
  SCRIPT = File.expand_path("update-homebrew-formula.rb", __dir__)
  ARM64_SHA256 = "a" * 64
  X86_64_SHA256 = "b" * 64

  FORMULA = <<~RUBY
    class AgentKeychain < Formula
      desc "Project-scoped credential and browser-session isolation for local AI agents"
      homepage "https://github.com/brynary/agent-keychain"
      url "ssh://git@github.com/brynary/agent-keychain.git",
          tag:      "v0.3.0",
          revision: "5d35722da61300ad020223cff33ca6ade92cf48e"
      license "MIT"
      head "ssh://git@github.com/brynary/agent-keychain.git", branch: "main"

      depends_on macos: :sonoma
    end
  RUBY

  def test_replaces_source_release_with_arch_specific_prebuilt_assets
    Dir.mktmpdir do |dir|
      formula_path = File.join(dir, "agent-keychain.rb")
      File.write(formula_path, FORMULA)

      _stdout, stderr, status = Open3.capture3(
        "ruby",
        SCRIPT,
        formula_path,
        "v1.2.3",
        ARM64_SHA256,
        X86_64_SHA256
      )

      assert status.success?, stderr

      formula = File.read(formula_path)
      assert_includes formula, '  version "1.2.3"'
      assert_includes formula, "  if Hardware::CPU.arm?"
      assert_includes formula, '    url "https://github.com/brynary/agent-keychain/releases/download/v1.2.3/agent-keychain-1.2.3-macos-arm64.tar.gz"'
      assert_includes formula, "    sha256 \"#{ARM64_SHA256}\""
      assert_includes formula, "  else"
      assert_includes formula, '    url "https://github.com/brynary/agent-keychain/releases/download/v1.2.3/agent-keychain-1.2.3-macos-x86_64.tar.gz"'
      assert_includes formula, "    sha256 \"#{X86_64_SHA256}\""
      assert_includes formula, '  head "ssh://git@github.com/brynary/agent-keychain.git", branch: "main"'
      refute_includes formula, "  on_arm do"
      refute_includes formula, "  on_intel do"
      refute_includes formula, "      tag:"
      refute_includes formula, "      revision:"
    end
  end

  def test_rejects_non_sha256_checksum
    Dir.mktmpdir do |dir|
      formula_path = File.join(dir, "agent-keychain.rb")
      File.write(formula_path, FORMULA)

      _stdout, stderr, status = Open3.capture3(
        "ruby",
        SCRIPT,
        formula_path,
        "v1.2.3",
        "not-a-checksum",
        X86_64_SHA256
      )

      refute status.success?
      assert_includes stderr, "arm64 SHA256 must be 64 hexadecimal characters"
    end
  end
end
