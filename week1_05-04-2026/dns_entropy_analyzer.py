import tldextract
import math
from collections import Counter

def calculate_entropy(domain_string):
    # Empty -> 0
    if not domain_string:
        return 0

    entropy = 0
    length = len(domain_string) # Total length

    # Counter for each letter appear and their frequency
    character_counts = Counter(domain_string)

    # Loop cal Sigma (∑)
    for count in character_counts.values():
        # 1.  p(x_i)
        p_x = count / length

        # 2. Formula: - p(x_i) * log2( p(x_i) ) and cal the sum
        entropy += - p_x * math.log2(p_x)

    return round(entropy, 3) # Round to 3 decimal places for better readability

def analysis_domain(url):
    # Function extract automatically url
    require = tldextract.extract(url)

    print(f"Analyzing: {url}")
    print(f"[1] Subdomain : '{require.subdomain}' ")
    print(f"[2] Domain  : '{require.domain}'")
    print(f"[3] Suffix    : '{require.suffix}'")
    print("-" * 60)

    # Return subdomain for further analysis
    return require.subdomain

# Demo
url_1 = "translate.google.com"
url_2 = "thanhnien.com.vn"
url_3 = "congtacvien.osbholding.com"
url_4 = "bWF0X2toYXU=.badguy.net"

# Analyzing and calculating entropy for each subdomain
sub_1 = analysis_domain(url_1)
sub_2 = analysis_domain(url_2)
sub_3 = analysis_domain(url_3)
sub_4 = analysis_domain(url_4)

for sub in [sub_1, sub_2, sub_3, sub_4]:
    print(f"Entropy of '{sub}': {calculate_entropy(sub)}")
    print("-" * 60)


print(f"\n=== EVALUATION RESULTS (Dual Analysis: Length + Entropy) ===")
for sub in [sub_1, sub_2, sub_3, sub_4]:
    
    # Skip domains that have no subdomain (like thanhnien.com.vn)
    if not sub:
        continue 
        
    score = calculate_entropy(sub)
    sub_length = len(sub)
    
    # DETECTION RULE: Subdomain must be long AND highly chaotic
    if sub_length >= 15 and score >= 3.5:
        print(f"[MALWARE ALERT]: '{sub}'")
        print(f"Reason: Subdomain is unusually long ({sub_length} chars) and highly chaotic (Entropy: {score})")
    
    elif score >= 3.2:
        print(f"[MONITORING REQUIRED]: '{sub}'")
        print(f"Reason: High entropy ({score}) but length is not yet critical ({sub_length} chars).")
        
    else:
        print(f"[SAFE]: '{sub}' (Entropy: {score}, Length: {sub_length})")