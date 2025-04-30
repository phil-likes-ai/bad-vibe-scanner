# src/bad.py
def long_ass_function_a(a, b, c, d, e, f):
    x = eval("1+1")  # HIGH severity
    print("yo")
    y = []  # No asserts, drags on
    for i in range(100):
        y.append(i)
    return y


def long_ass_function_b(a, b, c, d, e, f):
    x = eval("1+1")  # BS009: eval call
    print("yo")
    y = []  # BS011: unused local
    for i in range(100):
        y.append(i)
    return y
