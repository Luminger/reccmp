/* Minimal DOS/4GW program for reccmp LE format testing.
   Two exported functions so we can test symbol matching,
   one data symbol so we can test data section handling,
   and a fixup (pointer to data) so we can test is_relocated_addr(). */

int answer = 42;
int *answer_ptr = &answer;   /* fixup: pointer into data segment */

int add(int a, int b) {
    return a + b;
}

int get_answer(void) {
    return *answer_ptr;
}

int main(void) {
    return add(get_answer(), 1);
}
