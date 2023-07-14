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
2. removing array and join
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
     
