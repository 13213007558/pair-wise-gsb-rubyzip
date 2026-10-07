# frozen_string_literal: true

module Zip
  # Error raised when creating or applying a zip archive delta fails.
  # This includes malformed delta data, a base archive that does not match
  # the identity recorded in the delta, or a failed reuse precondition.
  class DeltaError < Error; end
end
