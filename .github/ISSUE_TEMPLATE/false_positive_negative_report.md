---
name: False positive / negative Report
about: Report a false positive / negative found by Nikto
title: 'False Positive/Negative: '
labels: bug
assignees: ''

---

### Output of suspected false positive / negative

Post any useful information like the ID of the test causing the false positive.

### Debug output

Run:

```
./nikto.pl -host targethost -Save false_positive
```

This saves all positive responses to a new `false_positive` directory. Afterwards look
for the related ID of the false positive / negative and paste it below.
