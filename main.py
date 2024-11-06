from chain import Chain

def main():
    blockchain = Chain()
    print("Blockchain initialized. Press 1 to add a block.")

    while True:
        pressedButton = int(input("Enter 1 to add a block: "))
        if pressedButton == 1:
            data = input("Enter data for the block: ")
            blockchain.addBlock(data)
            print("Block added.")

if __name__ == "__main__":
    main()





    


    



