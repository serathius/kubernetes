import re
import sys

def parse_histogram(text_data):
    """
    Parses Prometheus histogram text data to extract buckets, count, and sum.
    
    Args:
        text_data (str): The string containing the Prometheus histogram data.

    Returns:
        tuple: A tuple containing (sorted_buckets, total_count, total_sum).
               Returns (None, None, None) if parsing fails.
    """
    buckets = []
    total_count = None
    total_sum = None
    
    # Regex to capture the 'le' (less than or equal to) value and the cumulative count
    bucket_regex = re.compile(r'.*_bucket{le="([^"]+)"}\s+([\d\.]+)')
    # Regex to capture the total count of observations
    count_regex = re.compile(r'.*_count\s+([\d\.]+)')
    # Regex to capture the sum of all observation values
    sum_regex = re.compile(r'.*_sum\s+([\d\.]+)')

    for line in text_data.strip().split('\n'):
        # Skip comment lines
        if line.startswith('#'):
            continue
        
        bucket_match = bucket_regex.match(line)
        if bucket_match:
            le_str, count_str = bucket_match.groups()
            # Convert upper bound 'le' to a float, treating '+Inf' as infinity
            upper_bound = float('inf') if le_str == '+Inf' else float(le_str)
            count = int(float(count_str))
            buckets.append((upper_bound, count))
            continue
        
        count_match = count_regex.match(line)
        if count_match:
            total_count = int(float(count_match.group(1)))
            continue

        sum_match = sum_regex.match(line)
        if sum_match:
            total_sum = float(sum_match.group(1))
            continue

    if not buckets or total_count is None:
        return None, None, None
        
    # Sort buckets by their upper bound, which is crucial for calculation
    buckets.sort(key=lambda x: x[0])
    
    return buckets, total_count, total_sum


def calculate_percentiles(percentiles, buckets, total_count):
    """
    Calculates the latency values for given percentiles from histogram buckets.
    
    This function uses linear interpolation for a more accurate estimation.

    Args:
        percentiles (list): A list of percentiles to calculate (e.g., [50, 90, 99]).
        buckets (list): A sorted list of (upper_bound, cumulative_count) tuples.
        total_count (int): The total number of observations.

    Returns:
        dict: A dictionary mapping each percentile to its calculated value.
    """
    if total_count == 0:
        return {p: 0 for p in percentiles}

    results = {}
    
    for p in percentiles:
        if p < 0 or p > 100:
            raise ValueError("Percentile must be between 0 and 100")
            
        # Determine the rank (the observation number) for the percentile
        rank = (p / 100.0) * total_count
        
        # Find the bucket where the rank falls
        prev_bound = 0
        prev_count = 0
        
        found_bucket = False
        for upper_bound, count in buckets:
            if count >= rank:
                # This is the bucket that contains our percentile rank.
                # Now, perform linear interpolation to estimate the value.
                
                # How many observations are just in this bucket?
                count_in_bucket = count - prev_count
                if count_in_bucket <= 0:
                    # If no observations are in this bucket, the value is the previous bucket's bound
                    results[p] = prev_bound
                    found_bucket = True
                    break
                
                # How far into this bucket is our rank?
                rank_in_bucket = rank - prev_count
                # What is the width of this bucket's value range?
                bucket_width = upper_bound - prev_bound
                
                # Interpolate the value
                estimated_value = prev_bound + (rank_in_bucket / count_in_bucket) * bucket_width
                results[p] = estimated_value
                found_bucket = True
                break
            
            prev_bound = upper_bound
            prev_count = count
        
        if not found_bucket:
             # This case would typically only be hit if rank > total count, 
             # but we'll use the last finite bucket bound as the best estimate.
            results[p] = prev_bound

    return results

# --- Main execution ---
if __name__ == "__main__":
    # Example input data provided by the user
    histogram_data = """
# HELP controller_manager_watch_delay_total_seconds [ALPHA] Watch delay seconds
# TYPE controller_manager_watch_delay_total_seconds histogram
controller_manager_watch_delay_total_seconds_bucket{le="1"} 154946
controller_manager_watch_delay_total_seconds_bucket{le="2"} 178991
controller_manager_watch_delay_total_seconds_bucket{le="3"} 181517
controller_manager_watch_delay_total_seconds_bucket{le="4"} 184665
controller_manager_watch_delay_total_seconds_bucket{le="5"} 187010
controller_manager_watch_delay_total_seconds_bucket{le="6"} 189349
controller_manager_watch_delay_total_seconds_bucket{le="7"} 191111
controller_manager_watch_delay_total_seconds_bucket{le="8"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="9"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="10"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="11"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="12"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="13"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="14"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="15"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="16"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="17"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="18"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="19"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="20"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="21"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="22"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="23"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="24"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="25"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="26"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="27"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="28"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="29"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="30"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="31"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="32"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="33"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="34"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="35"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="36"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="37"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="38"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="39"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="40"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="41"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="42"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="43"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="44"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="45"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="46"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="47"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="48"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="49"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="50"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="51"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="52"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="53"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="54"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="55"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="56"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="57"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="58"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="59"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="60"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="61"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="62"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="63"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="64"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="65"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="66"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="67"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="68"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="69"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="70"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="71"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="72"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="73"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="74"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="75"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="76"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="77"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="78"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="79"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="80"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="81"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="82"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="83"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="84"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="85"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="86"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="87"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="88"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="89"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="90"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="91"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="92"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="93"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="94"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="95"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="96"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="97"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="98"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="99"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="100"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="101"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="102"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="103"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="104"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="105"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="106"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="107"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="108"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="109"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="110"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="111"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="112"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="113"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="114"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="115"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="116"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="117"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="118"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="119"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="120"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="121"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="122"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="123"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="124"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="125"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="126"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="127"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="128"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="129"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="130"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="131"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="132"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="133"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="134"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="135"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="136"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="137"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="138"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="139"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="140"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="141"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="142"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="143"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="144"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="145"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="146"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="147"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="148"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="149"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="150"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="151"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="152"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="153"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="154"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="155"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="156"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="157"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="158"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="159"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="160"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="161"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="162"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="163"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="164"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="165"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="166"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="167"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="168"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="169"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="170"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="171"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="172"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="173"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="174"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="175"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="176"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="177"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="178"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="179"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="180"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="181"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="182"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="183"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="184"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="185"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="186"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="187"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="188"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="189"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="190"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="191"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="192"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="193"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="194"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="195"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="196"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="197"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="198"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="199"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="200"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="201"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="202"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="203"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="204"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="205"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="206"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="207"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="208"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="209"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="210"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="211"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="212"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="213"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="214"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="215"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="216"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="217"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="218"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="219"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="220"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="221"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="222"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="223"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="224"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="225"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="226"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="227"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="228"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="229"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="230"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="231"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="232"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="233"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="234"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="235"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="236"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="237"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="238"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="239"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="240"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="241"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="242"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="243"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="244"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="245"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="246"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="247"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="248"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="249"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="250"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="251"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="252"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="253"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="254"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="255"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="256"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="257"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="258"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="259"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="260"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="261"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="262"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="263"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="264"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="265"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="266"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="267"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="268"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="269"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="270"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="271"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="272"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="273"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="274"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="275"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="276"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="277"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="278"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="279"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="280"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="281"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="282"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="283"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="284"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="285"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="286"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="287"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="288"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="289"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="290"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="291"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="292"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="293"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="294"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="295"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="296"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="297"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="298"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="299"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="300"} 191274
controller_manager_watch_delay_total_seconds_bucket{le="+Inf"} 191274
controller_manager_watch_delay_total_seconds_sum 163431.7357747132
controller_manager_watch_delay_total_seconds_count 191274

"""
    
    # You can also read from a file or stdin like this:
    # with open('metrics.txt', 'r') as f:
    #     histogram_data = f.read()
    # or
    # histogram_data = sys.stdin.read()

    buckets, total_count, total_sum = parse_histogram(histogram_data)

    if buckets:
        # Define which percentiles you want to calculate
        percentiles_to_calculate = [50, 90, 95, 99, 99.9]
        
        # Calculate the results
        latency_percentiles = calculate_percentiles(
            percentiles_to_calculate, buckets, total_count
        )
        
        print("--- Latency Percentiles ---")
        for p, value in latency_percentiles.items():
            print(f"p{p}: {value:.4f} seconds")
        print("---------------------------")

        # Additionally, calculate and display the average latency
        if total_sum is not None and total_count > 0:
            average_latency = total_sum / total_count
            print(f"Average: {average_latency:.4f} seconds")
        
        print(f"Total Count: {total_count}")

    else:
        print("Failed to parse histogram data.", file=sys.stderr)
