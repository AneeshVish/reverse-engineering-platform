def greet(name):
    print(f"Hello, {name}!")

def main():
    greet("World")
    for i in range(5):
        print(f"Fibonacci({i}) = {fibonacci(i)}")

def fibonacci(n):
    if n <= 1:
        return n
    return fibonacci(n - 1) + fibonacci(n - 2)

if __name__ == "__main__":
    main()
