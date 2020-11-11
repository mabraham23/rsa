# goal: receive a large peice of text via email from Bart and decrypt it here and send it back to him unencrypted
import other_millers
from math import gcd as bltin_gcd


class RSA:

    def toBase10(self, n, alphabet):
        a = 0
        for c in n:
            pos = alphabet.find(c)
            a *= len(alphabet)
            a += pos
        return a

    def fromBase10(self, n, alphabet):
        string = ""
        while n:
            pos = int(n % len(alphabet))
            string += alphabet[pos]
            n //= len(alphabet)
        return(string[::-1])

    def gcdExtended(self, a, b):
        # Base Case
        if a == 0:
            return b, 0, 1

        gcd, x1, y1 = self.gcdExtended(b % a, a)

        # Update x and y using results of recursive
        # call
        x = y1 - (b//a) * x1
        y = x1

        return gcd, x, y

    def coprime2(self, a, b):
        return bltin_gcd(a, b) == 1

    # Write a method called GenerateKeys that takes two very long text strings as input.
    def GenerateKeys(self, txt1, txt2):
        # Treat the text strings as base 26 numbers, and convert them to base 10 numbers
        alphabet = "abcdefghijklmnopqrstuvwxyz"
        txt1_base10 = self.toBase10(txt1, alphabet)
        txt2_base10 = self.toBase10(txt2, alphabet)

        # mod by 10^200 to make them the right size. Ensure that they were
        # longer than 10^200 before doing the mod, or print a Warning message.
        if txt1_base10 >= 10**200:
            right_size_1 = txt1_base10 % 10**200
        else:
            print("number 1 not longer than 10^200")

        if txt2_base10 >= 10**200:
            right_size_2 = txt2_base10 % 10**200
        else:
            print("number 2 not longer than 10^200")

        # Make them odd. Then start adding 2 until they are prime.
        if right_size_1 % 2 == 0:
            right_size_1 += 1
        if right_size_2 % 2 == 0:
            right_size_2 += 1

        # check against millers algorithm and add 2 until they become prime
        while other_millers.main([right_size_1]) == False:
            right_size_1 += 2
        while other_millers.main([right_size_2]) == False:
            right_size_2 += 2

        # Now you have your two, 200 digit prime numbers, p and q.
        # Calculate n = p*q
        n = right_size_1 * right_size_2
        # Calculate r = (p-1)*(q-1)
        r = (right_size_1 - 1) * (right_size_2 - 1)
        # Find e – a 398 digit number that is relatively prime with r.
        q = 13810834549851754495631119119083264472163086356572107773582879923426598025862074679447336117815943749541796279436443039552933969374169788367012246195789046529533631022625525345800281418485860410760897
        g = 1369130379653907728220329653863601998483759642997963321041916329355276363438824464509428450695834115276233573893780672690364403286484684834222612116667518454320778609664308572695691597523768521935011
        e = q * g
        if e % 2 == 0:
            e += 1
        while other_millers.main([e]) == False:
            e += 2
        # n = int(input("Enter number:"))
        s = e
        count = 0
        while(s > 0):
            count = count+1
            s = s//10
        # Find d – the inverse of e mod r.
        g, x, d = self.gcdExtended(r, e)

        # Save n and e to a file called public.txt (write them as text, with 1 return after each number)
        f = open("public.txt", "w")
        f.write(str(n))
        f.write("\n")
        f.write(str(e))
        f.close()

        # Save n and d to a file called private.txt
        fw = open("private.txt", "w")
        fw.write(str(n))
        fw.write("\n")
        fw.write(str(d))
        fw.close()
        # All other variables can be discarded.

    # Write a method called Encrypt that takes as parameters the name of an input text file and the name of an output text file.
    def Encrypt(self, inputfile, outputfile):
        # Open the input file (which should already exist in the current directory and
        # be full of plain text). Use binary mode, then convert the contents to text mode as follows:
        fin = open(inputfile, "rb")
        PlainTextBinary = fin.read()
        PlainText = PlainTextBinary.decode("utf-8")
        fin.close()
        alphabet = ".,?! \t\n\rabcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        # Treat the input file text as a base 70 integer, and convert it to base 10,
        # using block sizes so as to not exceed integer n.
        public = open("public.txt")
        file_contents = public.read()
        contents = file_contents.splitlines()
        n = contents[0]
        e = contents[1]

        size_chunk = 216
        chunks = [PlainText[i:i+size_chunk]
                  for i in range(0, len(PlainText), size_chunk)]

        # Encode each block using the rules of RSA.  (Read n and e from public.txt)
        fout = open(outputfile, "wb")
        i = 0
        money = "$"
        for i in range(len(chunks)):
            chunks[i] = self.toBase10(chunks[i], alphabet)
            chunks[i] = pow(int(chunks[i]), int(e), int(n))
            chunks[i] = self.fromBase10(chunks[i], alphabet)
            fout.write(chunks[i].encode("utf-8"))
            fout.write(money.encode("utf-8"))
        fout.close()

    # Write a method called Decrypt that takes as parameters the name of an input text file and the name of an output text file.
    def Decrypt(self, input, output):
        # Open the input file in binary mode (which should already exist and be full of encrypted text).
        # Use the same alphabet as above.
        fin = open(input, "rb")
        PlainTextBinary = fin.read()
        PlainText = PlainTextBinary.decode("utf-8")
        fin.close()
        alphabet = ".,?! \t\n\rabcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        # Treat the input file text as a base 70 integer, and convert it to base 10, using block sizes as indicated by the $ signs.
        blocks = PlainText.split("$")
        # Decode each block using the rules of RSA.  (Read n and d from private.txt)
        public = open("private.txt")
        file_contents = public.read()
        contents = file_contents.splitlines()
        n = contents[0]
        d = contents[1]
        fout = open(output, "wb")
        i = 0
        for i in range(len(blocks)):
            blocks[i] = self.toBase10(blocks[i], alphabet)
            blocks[i] = pow(blocks[i], int(d), int(n))
            blocks[i] = self.fromBase10(blocks[i], alphabet)
            fout.write(blocks[i].encode("utf-8"))
        fout.close()


def main():
    # Write a main function to test your codeour code
    # Make a class of type RSA
    # Generate the key files by calling GenerateKeys with two
    # very long strings of lowercase letters that only you would remember.
    # rsa.GenerateKeys("long text that only i remeber",
    #                  "long text that only i remember")

    rsa = RSA()
    rsa.GenerateKeys("viqopcxkqcomyyootqgqjoiiojtcamjfxflupncosozuiwseohhmhryzbxntwnkqxjbvntnzowoolihicjhnepqsmbkpahidrsyatybejuxfikrudqquahznvqmfxhcbuussqqasojwpskbgwsruzqzywbyehhrhxboplhxyzbrqokuqewcddy",
                     "qwxaohhoolmdcngmrnzjefsmcskldwwlokdwlczldssmpwdpwfycojxdgkvenlzoksancwtjgtkihytjbpwpiahqjuvkppkbnawxtuzpiuiobdltfqkfhpyeqxdqhwtlwuazokucfvafkknsikvfhwygebgitkzgvtxlnbcwsymhfvzuftbiw")
    rsa.Encrypt("message.txt", "encrypted.txt")
    rsa.Decrypt("encrypted.txt", "decrypted.txt")


    # Make a plain text file consisting of only letters in the alphabet.
    # It should be long enough to require multiple encoding blocks.
    # Call your Encrypt method.
    # Call your Decrypt method.
    # Verify that the decoded output file exactly matches the original plain text file.
main()

# to pass off
# Email me your public.txt (not private.txt)
# I will use that to send you a message that only you can decrypt.
# Email me back the decrypted message

# All code should be of your own creation, except the Inverse Euclidean Algorithm, which you may get whatever help you can from the internet.
