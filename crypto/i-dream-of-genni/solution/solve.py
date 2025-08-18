pairs = [(x,y) for x in range(1,10) for y in range(1,10) if x*y >= 10]

def multwo(i, j, digits):
    s, mul = 0, 1
    for z in range((digits+1)//2):
        s += (i % 10) * (j % 10) * mul
        i, j, mul = i // 10, j // 10, mul * 100
    return s

def process(x, y, digits, N = 7):
    if digits == N:
        n1 = x*y - multwo(x,y,N*2)
        n2 = 10**N * (10**N - y)
        if n1 < 10 * n2 and n1 % n2 == 0:
            print(f'{n1//n2}{x}, {y}')
        return       
    mul = 10**digits
    for a, b in pairs:
        x2 = a*mul + x
        y2 = b*mul + y
        if (multwo(x2, y2, digits+1) - x2*y2) % (10*mul) == 0:
            process(x2, y2, digits+1)

process(0,0,0)

# this script prints out two solutions:
# 49228443, 9773647
# 39876877, 9564546
# the second one is from the image, so we use the first one