require 'bundler/setup'
Bundler.setup

require 'dotenv'
Dotenv.load('.env.test')

# Load the main file
require_relative '../jwt_validator'

RSpec.configure do |config|
  # Enable flags like --only-failures and --next-failure
  config.example_status_persistence_file_path = '.rspec_status'

  # Disable RSpec exposing methods globally on `Object` and `main`
  config.disable_monkey_patching!

  config.expect_with :rspec do |c|
    c.syntax = :expect
  end

  # Configure WebMock
  config.before(:each) do
    WebMock.disable_net_connect!(allow_localhost: true)
  end
end 