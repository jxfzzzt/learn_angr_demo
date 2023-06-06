import angr

def main():
    proj = angr.Project('06_angr_symbolic_dynamic_memory')
    start_addr = 0x08048699
    init_state = proj.factory.blank_state(addr=start_addr)
    buffer0_addr = 0x0ABCC8A4
    buffer1_addr = 0x0ABCC8AC

    esp_addr = init_state.regs.esp.args[0] # 获得esp地址
    malloc0_addr = esp_addr - 0x100 # 随便选取一个地址作为malloc的地址
    malloc1_addr = esp_addr - 0x200

    init_state.memory.store(buffer0_addr, malloc0_addr, endness=proj.arch.memory_endness)
    init_state.memory.store(buffer1_addr, malloc1_addr, endness=proj.arch.memory_endness)

    s_size = 8 * 8
    pass1 = init_state.solver.BVS('pass1', s_size)
    pass2 = init_state.solver.BVS('pass2', s_size)

    init_state.memory.store(malloc0_addr, pass1)
    init_state.memory.store(malloc1_addr, pass2)

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
        print('Solution: {} {}'.format(password1, password2))
    else:
        raise Exception("Solution not found")

if __name__ == '__main__':
    main()