def run_report(username)
  output = `report-tool --user=#{username}`
  puts output
end
