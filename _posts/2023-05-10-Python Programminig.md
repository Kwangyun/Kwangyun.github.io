Test:
## Reverse A linked List:
#### Things to note
1. Two Pointer Question
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