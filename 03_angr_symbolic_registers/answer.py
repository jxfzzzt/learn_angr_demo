import angr

def main():
    proj = angr.Project('03_angr_symbolic_registers')
    start_addr = 0x08048980
    init_state = proj.factory.blank_state(addr=start_addr)

    reg_size = 4 * 8
    pass1 = init_state.solver.BVS('pass1', reg_size)
    pass2 = init_state.solver.BVS('pass2', reg_size)
    pass3 = init_state.solver.BVS('pass3', reg_size)

    init_state.regs.eax = pass1
    init_state.regs.ebx = pass2
    init_state.regs.edx = pass3

    sm = proj.factory.simulation_manager(init_state)

    def is_good(state):
        return b'Good Job' in state.posix.dumps(1)

    def is_bad(state):
        return b'Try again' in state.posix.dumps(1)

    sm.explore(find=is_good, avoid=is_bad)

    if sm.found:
        found_state = sm.found[0]
        password1 = found_state.solver.eval(pass1)
        password2 = found_state.solver.eval(pass2)
        password3 = found_state.solver.eval(pass3)
        print('Solution: {:x} {:x} {:x}'.format(password1, password2, password3))
    else:
        raise Exception("Solution not found")

if __name__ == '__main__':
    main()