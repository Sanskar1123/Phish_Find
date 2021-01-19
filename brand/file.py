fopen = open("brand.txt")

for i in fopen:
    i = i.rstrip()
    i = i.lower()
    name = i + ".txt"
    fbrand = open(name , "w+")
    fbrand.close()
