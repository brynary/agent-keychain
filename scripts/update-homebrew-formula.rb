#!/usr/bin/env ruby
# frozen_string_literal: true

RELEASE_BASE_URL = "https://github.com/brynary/agent-keychain/releases/download"
ASSET_NAME = "agent-keychain"
FORMULA_USAGE = "Usage: update-homebrew-formula.rb FORMULA_PATH RELEASE_TAG ARM64_SHA256 X86_64_SHA256"

formula_path, release_tag, arm64_sha256, x86_64_sha256 = ARGV
abort FORMULA_USAGE unless formula_path && release_tag && arm64_sha256 && x86_64_sha256
abort "Release tag must start with v: #{release_tag}" unless release_tag.start_with?("v")
abort "arm64 SHA256 must be 64 hexadecimal characters: #{arm64_sha256}" unless arm64_sha256.match?(/\A[0-9a-f]{64}\z/i)
abort "x86_64 SHA256 must be 64 hexadecimal characters: #{x86_64_sha256}" unless x86_64_sha256.match?(/\A[0-9a-f]{64}\z/i)

version = release_tag.delete_prefix("v")
stable_release = [
  "  version \"#{version}\"",
  "",
  "  if Hardware::CPU.arm?",
  "    url \"#{RELEASE_BASE_URL}/#{release_tag}/#{ASSET_NAME}-#{version}-macos-arm64.tar.gz\"",
  "    sha256 \"#{arm64_sha256}\"",
  "  else",
  "    url \"#{RELEASE_BASE_URL}/#{release_tag}/#{ASSET_NAME}-#{version}-macos-x86_64.tar.gz\"",
  "    sha256 \"#{x86_64_sha256}\"",
  "  end"
].join("\n")

formula = File.read(formula_path)
formula_parts = formula.match(/\A(?<prefix>.*?^  homepage "[^"]+"\n)(?<stable>.*?)(?<suffix>^  license .*)\z/m)
abort "Unable to find Homebrew homepage/license declarations in #{formula_path}" unless formula_parts

updated_formula = "#{formula_parts[:prefix]}#{stable_release}\n\n#{formula_parts[:suffix]}"

File.write(formula_path, updated_formula)
