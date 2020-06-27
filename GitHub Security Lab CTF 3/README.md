# Link to the CTF:
https://securitylab.github.com/ctf/jquery
# Answer:
**_(Step by step)_**
### Question 0.0:
https://lgtm.com/query/2944505928281948913/
### Question 0.1:
https://lgtm.com/query/94632149398331136/
### Question 0.2:
https://lgtm.com/query/1033784391523880075/
### Question 1.0:
https://lgtm.com/query/6740581844299341542/
### Question 1.1:
https://lgtm.com/query/9062935539504101478/
### Question 1.2:
https://lgtm.com/query/8563304383211677815/
### Question 1.3:
https://lgtm.com/query/7443215202330857965/
### Question 2.0:
https://lgtm.com/query/3691857042911406798/
### Question 2.1:
* Unpatched version:

File | Line | Classification | Explanation
-----|------|----------------|------------
js/affix.js | 19 | True positive | CVE-2018-20677
js/collapse.js | 140 | True positive | CVE-2018-14040
js/scrollspy.js | 113 | True positive | The payload will be triggered after the website loads.
js/scrollspy.js | 127 | True positive | The payload will be triggered when users scroll to the website's bottom.
js/tooltip.js | 54 | True positive | CVE-2018-20676
js/tooltip.js | 207 | False negative | My query does not handle flow through ternary operators.

* Patched version:

File | Line | Classification | Explanation
-----|------|----------------|------------
js/affix.js | 19 | False positive | My query flags all arguments to $, regardless of their origin.
js/scrollspy.js | 113 | True positive | The payload will be triggered after the website loads.
js/scrollspy.js | 127 | True positive | The payload will be triggered when users scroll to the website's bottom.

### Question 3.0:
The unpatched variants are the two at js/scrollspy.js.  
How to exploit: Insert payload into data-target.  
For example, use this demo: https://jsbin.com/sajonenemo/edit?html,output  
The fixes should be:  
$(selector) --> $(document).find(selector)  
$(this.selector) --> $(document).find(this.selector)  
### Question 3.1:
https://lgtm.com/query/9120655107241544464/
### Question 3.2:
* Unpatched version:

File | Line | Classification | Explanation
-----|------|----------------|------------
js/affix.js | 19 | True positive | CVE-2018-20677
js/collapse.js | 140 | True positive | CVE-2018-14040
js/scrollspy.js | 113 | True positive | The payload will be triggered after the website loads.
js/scrollspy.js | 127 | True positive | The payload will be triggered when users scroll to the website's bottom.
js/tooltip.js | 54 | True positive | CVE-2018-20676
js/tooltip.js | 207 | True positive | CVE-2018-14042
js/tooltip.js | 432 | False positive | The payload will be triggered when users hover mouse on the link. However, this plugin option is intended to interpret as HTML by the programmer..

* Patched version:

File | Line | Classification | Explanation
-----|------|----------------|------------
js/affix.js | 19 | False positive | My query flags all arguments to $, regardless of their origin.
js/scrollspy.js | 113 | True positive | The payload will be triggered after the website loads.
js/scrollspy.js | 127 | True positive | The payload will be triggered when users scroll to the website's bottom.
js/tooltip.js | 432 | False positive | The payload will be triggered when users hover mouse on the link. However, this plugin option is intended to interpret as HTML by the programmer..

### Question 4.0:
https://lgtm.com/query/7129699633238675782/
### Question 4.1:
https://lgtm.com/query/7837905597242666486/
### Question 4.2:
https://lgtm.com/query/8981783563642684077/
### Question 4.3 (Final):
https://lgtm.com/query/543443028392613541/
