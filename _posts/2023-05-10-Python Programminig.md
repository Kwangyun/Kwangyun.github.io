Test:
## Reverse A linked List:
#### Things to note
1. Dummy node
3. Two Pointer Question
2. Temp vairiable to store node next
```bash
class Solution(object):
    def reverseList(self, head):
        prev= None
        curr= head
        
        while curr!=None:
            temp=curr.next
            curr.next=prev
            prev=curr
            curr=temp
            
        return prev
                 
```
## 35. Search Insert Position

1. Binary search
2. two pointer.
```bash
        left=0
        right=len(nums)-1
        while left<=right:
            mid= left+(right-left) /2 
            if target== nums[mid]:
                return mid
            if target> nums[mid]:
                left = mid+1
            if target < nums[mid]:
                right =mid-1 
        return left            

```
## Group Anagram
1. hashmap 
2. removing array and using ''.join
```
d = {}
for i in range(len(strs)):
x = ''.join(sorted(strs[i]))
    if x not in d:
        d[x]= [strs[i]]
    else:
    d[x].append(strs[i])
    return d.values()
```
     
## Encoding and Decoding
```bash
class Codec:

    def encode(self, strs):
        """Encodes a list of strings to a single string.
        
        :type strs: List[str]
        :rtype: str
        """
        if (len(strs)==0): 
            return null;
        else:
            return '-encodedString'.join(strs)
        

    def decode(self, s):
        """Decodes a single string to a list of strings.
        
        :type s: str
        :rtype: List[str]
        """
        if (len(s) == 0): return []
        return s.split("-encodedString")
        
```
IsPalinDrome
```

cleaned_s = ''.join(char.lower() for char in s if char.isalnum())
    
    
    left, right = 0, len(cleaned_s) - 1
    while left < right:
        if cleaned_s[left] != cleaned_s[right]:
            return False
        left += 1
        right -= 1
    
    return True
```