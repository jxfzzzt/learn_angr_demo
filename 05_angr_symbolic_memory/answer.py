import angr

def main():
    proj = angr.Project('05_angr_symbolic_memory')

    start_addr = 0x08048601
    init_state = proj.factory.blank_state(addr=start_addr)

    s_size = 8 * 8
    pass1 = init_state.solver.BVS('pass1', s_size)
    pass2 = init_state.solver.BVS('pass2', s_size)
    pass3 = init_state.solver.BVS('pass3', s_size)
    pass4 = init_state.solver.BVS('pass4', s_size)

    p_addr1 = 0x0A1BA1C0
    p_addr2 = 0x0A1BA1C8
    p_addr3 = 0x0A1BA1D0
    p_addr4 = 0x0A1BA1D8

    init_state.memory.store(p_addr1, pass1)
    init_state.memory.store(p_addr2, pass2)
    init_state.memory.store(p_addr3, pass3)
    init_state.memory.store(p_addr4, pass4)

    sm = proj.factory.simulation_manager(init_state)

    def is_good(state):
        return b'Good Job' in state.posix.dumps(1)

    def is_bad(state):
        return b'Try again' in state.posix.dumps(1)

    sm.explore(find=is_good, avoid=is_bad)
    if sm.found:
        found_state = sm.found[0]
        password1 = found_state.solver.eval(pass1, cast_to=bytes).decode('utf-8')
        password2 = found_state.solver.eval(pass2, cast_to=bytes).decode('utf-8')
        password3 = found_state.solver.eval(pass3, cast_to=bytes).decode('utf-8')
        password4 = found_state.solver.eval(pass4, cast_to=bytes).decode('utf-8')
        print('Solution: {} {} {} {}'.format(password1, password2, password3, password4))
        # Solution: NAXTHGNR JVSFTPWE LMGAUHWC XMDCPALU
    else:
        raise Exception('Solution not found')

if __name__ == '__main__':
    main()