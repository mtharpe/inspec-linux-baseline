# frozen_string_literal: true

require 'rubocop/rake_task'

RuboCop::RakeTask.new(:cookstyle) do |task|
  task.options = ['--display-cop-names']
end

desc 'Lint Ruby with Cookstyle'
task lint: [:cookstyle]

desc 'Validate the InSpec profile'
task :check do
  require 'inspec'
  puts "Checking profile with InSpec #{Inspec::VERSION}"
  profile = Inspec::Profile.for_target('.', backend: Inspec::Backend.create(Inspec::Config.mock))
  pp profile.check
end

task default: %i[lint check]
