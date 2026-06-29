#!/usr/bin/env ruby
# frozen_string_literal: true

SOURCE_URL = "ssh://git@github.com/brynary/agent-keychain.git"
FORMULA_USAGE = "Usage: update-homebrew-formula.rb FORMULA_PATH RELEASE_TAG RELEASE_REVISION"

formula_path, release_tag, release_revision = ARGV
abort FORMULA_USAGE unless formula_path && release_tag && release_revision
abort "Release tag must start with v: #{release_tag}" unless release_tag.start_with?("v")
abort "Release revision must be a 40-character commit SHA: #{release_revision}" unless release_revision.match?(/\A[0-9a-f]{40}\z/i)

stable_source = [
  "  url \"#{SOURCE_URL}\",",
  "      tag:      \"#{release_tag}\",",
  "      revision: \"#{release_revision}\""
].join("\n")

formula = File.read(formula_path)
stable_source_pattern = /^  url "#{Regexp.escape(SOURCE_URL)}",\n      tag:\s+"[^"]+",\n      revision: "[0-9a-fA-F]{40}"\n/

if formula.match?(stable_source_pattern)
  updated_formula = formula.sub(stable_source_pattern, "#{stable_source}\n")
elsif formula.match?(/^  license /)
  updated_formula = formula.sub(/^  license /, "#{stable_source}\n  license ")
elsif formula.match?(/^  head /)
  updated_formula = formula.sub(/^  head /, "#{stable_source}\n  head ")
else
  abort "Unable to find a Homebrew head declaration in #{formula_path}"
end

File.write(formula_path, updated_formula)
