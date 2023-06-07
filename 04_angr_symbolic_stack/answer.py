import angr


def main():
    proj = angr.Project('04_angr_symbolic_stack')

    start_addr = 0x08048697
    init_state = proj.factory.blank_state(addr=start_addr)

    padding_size = 0x0c - 4
    init_state.stack_push(init_state.regs.ebp)
    init_state.regs.ebp = init_state.regs.esp

    init_state.regs.esp -= padding_size

    u_size = 8 * 4
    pass1 = init_state.solver.BVS('pass1', u_size)
    pass2 = init_state.solver.BVS('pass2', u_size)

    init_state.stack_push(pass1)
    init_state.stack_push(pass2)


    def is_good(state):
        return b'Good Job' in state.posix.dumps(1)

    def is_bad(state):
        return b'Try again' in state.posix.dumps(1)

    sm = proj.factory.simulation_manager(init_state)
    sm.explore(find=is_good, avoid=is_bad)

    if sm.found:
        found_state = sm.found[0]
        password1 = found_state.solver.eval(pass1)
        password2 = found_state.solver.eval(pass2)
        print('Solution: {} {}'.format(password1, password2))
    else:
        raise Exception("Solution not found")

if __name__ == '__main__':
    main()