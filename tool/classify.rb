module Baffle
  def classify_device(probe_results)
    votes = Hash.new(0)
  
    probe_results.each do |probe_result|
      probe_result.hypotheses.each_pair do |device, confidence|
        votes[device] += probe_result.total_votes * confidence
      end
    end
    
    # return the key with the largest value in votes
    votes.max{|a, b| a[1] <=> b[1]}[0]
  end
end