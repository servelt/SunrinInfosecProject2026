typedef int (*operation_fn)(int);

static int add_one(int value) {
    return value + 1;
}

static int subtract_one(int value) {
    return value - 1;
}

int dispatch_indirect(int selector, int value) {
    operation_fn operation = selector ? add_one : subtract_one;
    return operation(value);
}
