module Baffle
  # The percentage of total votes by which the top candidate must exceed the second
  # candidate to win the vote
  VOTING_MARGIN = 0.1
  
  def classify_device(probe_results)
    votes = Hash.new(0)
    total_votes = 0
    
    probe_results.each do |probe_result|
      probe_result.hypotheses.each_pair do |device, confidence|
        votes[device] += probe_result.total_votes * confidence
      end
      
      total_votes += probe_result.total_votes
    end
    
    # return the key with the largest value in votes
    sorted_votes = votes.sort_by{|x| x[1]}
    
    if sorted_votes[-1][1] > sorted_votes[-2][1] + (total_votes / VOTING_MARGIN)
      sorted_votes[-1][0]
    else
      nil
    end
  end
end