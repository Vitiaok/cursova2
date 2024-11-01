import hashlib
import datetime as date

HASH_TARGET ="00000"

class Block:
    def __init__(self, index, timestamp, data, hash="0", previous_hash = None):
        self.index = index
        self.timestamp = timestamp
        self.data = data
        self.previousHash = previous_hash
        self.nonce = 0
        self.hash = hash

    def hashBlock(self):
        data = (str(self.index)+str(self.data)+str(self.timestamp)+
                str(self.previousHash)+str(self.nonce)).encode('utf-8')
        return hashlib.sha256(data).hexdigest()
    
class Chain:

    def __init__(self):
        self.blockchain = []
    
    def addBlock(self, data):
        if(len(self.blockchain) == 0):
            previous_hash = "0"*64
            newBlock = Block(len(self.blockchain), date.datetime.now(), data, previous_hash=previous_hash)
        else:
            previousBLock=self.blockchain[-1]
            newBlock = Block(len(self.blockchain), date.datetime.now(), data, previous_hash=previousBLock.hash)
        newBlock.hash = self.proofOfWork(newBlock)
        self.blockchain.append(newBlock)
    
    def getChain(self):
        return self.blockchain
    
    def proofOfWork(self, block):
        while block.hash[:len(HASH_TARGET)] != HASH_TARGET:
            block.nonce +=1
            block.hash = block.hashBlock()
        return block.hash
    
    def isValid(self):
        for i in range(1, len(self.blockchain)):
            currentBlock = self.blockchain[i]
            previousBlock = self.blockchain[i-1]
            if currentBlock.hash != currentBlock.hashBlock():
                return False
            if currentBlock.previousHash != previousBlock.hash:
                return False
            return True 
        
def main():
    blockchain = Chain()
    for i in range(3):
            blockchain.addBlock("{i} Block")
    for block in blockchain.getChain():
        print(block.index, block.timestamp, block.previousHash,
              block.hash, block.data, block.nonce)
        print(blockchain.isValid())


main()
    



