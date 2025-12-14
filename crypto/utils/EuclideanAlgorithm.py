#The Euclidean Algorithm (GCD)

# def GCD(A,B):
#     # they actually swap automatically in the first call 
#     #if B > A:
#      #   A, B = B, A
#     #print(f"A = {A} \nB = {B}")
#     if B == 0:
#         return A
#     r = A % B 
#     A = B
#     B = r
#     return GCD(A,B)
#--------------------------------------
# Upgraded version
def GCD(A,B):
    # they actually swap automatically in the first call 
    if B == 0:
        return A
    return GCD(B,A%B)


#A = 96 
#B = 18
#print(f"GCD({A}, {B}) = {GCD(A,B)}")

#The Extended Euclidean Algorithm
#Example: find a^(-1) mod b

def EEA (B,A):
    if GCD(A,B) != 1:
        return "there is no inverse"
    OA = A
    Q = A//B #int(A/B) uses floating-point division
    R = A%B
    T1 = 0
    T2 = 1
    T = T1-(T2 * Q)
    #print(f"Q A B R T1 T2 T")
    #print(f"{Q} {A} {B} {R} {T1}  {T2} {T}")
    while(R!=0):
        A=B
        B=R
        T1=T2
        T2=T
        R=A%B
        #print(f"R={R}")
        Q=int(A/B)
        T = T1-(T2 * Q)
        #print(f"{Q} {A} {B} {R} {T1}  {T2} {T}")
    if T2 <0:
        T2+= OA
    return T2

A = 7
B = 16
#print(f"EEA({A} mod({B}) ) = {EEA(A,B)}")
