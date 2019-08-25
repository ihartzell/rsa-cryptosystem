# Isaac Hartzell
# 7/19/2019
# CS 4290 Cryptography and Data Security Extra Credit 2
# This program decrypts an RSA system of block size 3 containing 232 cipher text words.


# I created this function because in order to decrypt all the cipher numbers in the RSA system I need to perform this
# algorithm.
def square_and_multiply(crypto_num):
    # This stays constant, I modulate every crypto number by this constant hence why it's here.
    N_PARAM = 18923
    # This gives a listing of the crypto numbers squared and multiplied.
    crypto_nums_squared_and_multiplied = perform_square_and_multiply(crypto_num, N_PARAM)
    # The final step of the algorithm is to take the correct bit pattern for what power the crypto number is raised to
    # which in this case is 5757, and multiply them all together.
    # I figured out that 5757 is 2^0 + 2^2 + 2^5 + 2^7 + 2^9 + 2^10 + 2^12, so that's why I'm multiplying the correct
    # elements together and modulating that to give the final_crypto_num before figuring out this number in
    # base 26 for decryption.
    final_crypto_num = (crypto_nums_squared_and_multiplied[0] * crypto_nums_squared_and_multiplied[2] *
                        crypto_nums_squared_and_multiplied[5] * crypto_nums_squared_and_multiplied[7] *
                        crypto_nums_squared_and_multiplied[9] * crypto_nums_squared_and_multiplied[10]
                        * crypto_nums_squared_and_multiplied[12]) % N_PARAM
    return final_crypto_num


# I made this function because I needed a way to perform the square and multiply algorithm concisely.
def perform_square_and_multiply(crypto_num, N_PARAM):
    # I need a container for all these square operations, so I can run the algorithm concisely in a loop.
    crypto_nums_squared_and_multiplied = []
    starting_crypto_num_raised2to_power = crypto_num**2**0
    crypto_nums_squared_and_multiplied.append(starting_crypto_num_raised2to_power)
    next_crypto_num_raised2to_power = (starting_crypto_num_raised2to_power**2) % N_PARAM
    crypto_nums_squared_and_multiplied.append(next_crypto_num_raised2to_power)
    for i in range(0, 11):
        # In order to perform the algorithm I need to square the previous item in the list and modulate that
        next_crypto_num_raised2to_power = (crypto_nums_squared_and_multiplied[-1]**2) % N_PARAM
        crypto_nums_squared_and_multiplied.append(next_crypto_num_raised2to_power)

    return crypto_nums_squared_and_multiplied


# Note about get_plaintext_letter_1-3: The crypto_num when ran through the square and multiply algorithm is a float,
# so I have to convert it to an integer so I can then turn it into a character by adding 97 to give the ASCII number
# for the plaintext letter I want. This is why I convert the crypto_num to an int and then a char.
# I made this function because I need a way of getting the first plaintext letter.
def get_plaintext_letter_1(crypto_num):
    crypto_letter1_as_float = (crypto_num / 26 ** 2)
    crypto_letter1_as_int = int(crypto_letter1_as_float)
    crypto_letter1_as_char = turn_int_into_char(crypto_letter1_as_int)
    return crypto_letter1_as_char


# I made this function because I need a way of getting the second plaintext letter
def get_plaintext_letter_2(crypto_num):
    crypto_num %= 26 ** 2
    crypto_letter2_as_float = (crypto_num / 26)
    crypto_letter2_as_int = int(crypto_letter2_as_float)
    crypto_letter2_as_char = turn_int_into_char(crypto_letter2_as_int)
    return crypto_letter2_as_char


# I made this because I need a way of getting the final plain text letter for a crypto number.
def get_plaintext_letter_3(crypto_num):
    crypto_num %= 26
    crypto_num = int(crypto_num)
    crypto_letter3_as_char = turn_int_into_char(crypto_num)
    return crypto_letter3_as_char


# This function was maid to give the whole plain text for a crypto number.
def get_plaintext(crypto_num):
    plaintext = []

    plaintext.append(get_plaintext_letter_1(crypto_num))
    plaintext.append(get_plaintext_letter_2(crypto_num))
    plaintext.append(get_plaintext_letter_3(crypto_num))

    return plaintext


# I'm making this function because I need to be able to turn an integer to the char representation for showing
# the plain text. The way this is done is by adding 97 and then using the chr() function to give the char of the
# ASCII representation.
def turn_int_into_char(int_to_char):
    int_to_char += 97
    int_to_char = chr(int_to_char)
    return int_to_char


# Start of program
def main():
    # This is the list of crypto numbers that when deciphered will give me the decrypted plain text
    # The block size is 3, so each of these crypto numbers should have 3 plain text letters associated with them.
    crypto_nums = [12423, 11524, 7243, 7459, 14303, 6127, 10964, 16399, 9792,
                   13629, 14407, 18817, 18830, 13556, 3159, 16647, 5300,
                   13951, 81, 8986, 8007, 13167, 10022, 17213, 2264,
                   961, 17459, 4101, 2999, 14569, 17183, 15827, 12693,
                   9553, 18194, 3830, 2664, 13998, 12501, 18873, 12161,
                   13071, 16900, 7233, 8270, 17086, 9792, 14266, 13236,
                   5300, 13951, 8850, 12129, 6091, 18110, 3332, 15061,
                   12347, 7817, 7946, 11675, 13924, 13892, 18031, 2620,
                   6276, 8500, 201, 8850, 11178, 16477, 10161, 3533,
                   13842, 7537, 12259, 18110, 44, 2364,
                   15570, 3460, 9886, 8687, 4481, 11231, 7547, 11383,
                   17910, 12867, 13203, 5102, 4742, 5053, 15407,
                   2976, 9330, 12192, 56, 2471, 15334, 841, 13995,
                   17592, 13297, 2430, 9741, 11675, 424, 6686, 738, 13874,
                   8168, 7913, 6246, 14301, 1144, 9056, 15967, 7328,
                   13203, 796, 195, 9872, 16979, 15404, 14130, 9105,
                   2001, 9792, 14251, 1498, 11296, 1105, 4502, 16979,
                   1105, 56, 4118, 11302, 5988, 3363, 15827, 6928,
                   4191, 4277, 10617, 874, 13211, 11821, 3090, 18110,
                   44, 2364, 15570, 3460, 9886, 9988, 3798, 1158,
                   9872, 16979, 15404, 6127, 9872, 3652, 14838, 7437,
                   2540, 1367, 2512, 14407, 5053, 1521, 297, 10935,
                   17137, 2186, 9433, 13293, 7555, 13618, 13000, 6490,
                   5310, 18676, 4782, 11374, 446, 4165, 11634, 3846,
                   14611, 2364, 6789, 11634, 4493, 4063, 4576, 17955,
                   7965, 11748, 14616, 11453, 17666, 925, 56, 4118,
                   18031, 9522, 14838, 7437, 3880, 11476, 8305, 5102,
                   2999, 18628, 14326, 9175, 9061, 650, 18110, 8720,
                   15404, 2951, 722, 15334, 841, 15610, 2443, 11056, 2186]
    # I need to hold all the crypto numbers after applying the square and multiply algorithm to each crypto number.
    square_and_multiply_results = []
    # These variables are created for my second for loop, so I can properly print out the list of crypto numbers.
    counter1 = 0
    counter2 = 8
    # This string was created because the plain text is currently in a list, and if I put the list elements in a string
    # I can more effectively print out the plaintext/decryption.
    plaintext = ''
    # I made this file because I want an easy way of printing out the plaintext for my professor.
    file = open("plaintext.txt", "w")
    # I'm cyling through the crypto_nums list so that I can put in a new list the new crypto list which has gone through
    # the square and multiply algorithm.
    for i in range(len(crypto_nums)):
        square_and_multiply_results.append(square_and_multiply(crypto_nums[i]))

    print('\n', "List of crypto numbers after performing square and multiply, and before deciphering.")
    print("------------------------------------------------------------------------------------")
    for i in range(int(len(crypto_nums)/8)):  # dividing by 8 so I don't get unnecessary new lines.
        # I wrote this so that there's 8 crypto numbers on one line, and they don't all print on one line.
        print(*square_and_multiply_results[counter1:counter2], sep=' ')
        counter1 += 8
        counter2 += 8

    print('\n', "The plain text.")
    print("---------------------")
    # I know need to go through the square_and_multiply_results to actually give the plain text.
    for i in range(len(square_and_multiply_results)):
        # Turning the list into a string, so it prints nicer without ,'s and []'s.
        plaintext += ''.join(get_plaintext(square_and_multiply_results[i]))

    # Resetting counters to reuse for next for loop.
    counter1 = 0
    counter2 = 8
    # Creating this counter, so that after I've printed my lines of 8 plaintext letters
    # which happens to be 87, I can exit the for loop, so I don't continually get new lines.
    exit_counter = 0
    # I'm now going through the list of plain text and printing them in characters of 8 per line for easier reading.
    for i in plaintext:
        print(plaintext[counter1:counter2])
        file.write(plaintext[counter1:counter2] + '\n')
        counter1 += 8
        counter2 += 8
        # Incrementing by 1 so that once 87 has been reached I know all plain text has been printed.
        exit_counter += 1
        if exit_counter is 87:
            exit(0)
            file.close()


# Where execution of program happens.
if __name__ == '__main__':
    main()
