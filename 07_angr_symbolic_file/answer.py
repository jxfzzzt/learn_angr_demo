import angr

def main():
    proj = angr.Project('07_angr_symbolic_file')
    start_addr = 0x080488D6
    init_state = proj.factory.blank_state(addr=start_addr)

    file_size = 0x40
    filename = 'OJKSQYDP.txt'

    pass1 = init_state.solver.BVS('pass1', file_size * 8)
    sim_file = angr.storage.SimFile(filename, content=pass1, size=file_size)
    init_state.fs.insert(filename, sim_file)

    def is_good(state):
        return b'Good Job' in state.posix.dumps(1)

    def is_bad(state):
        return b'Try again' in state.posix.dumps(1)

    sm = proj.factory.simulation_manager(init_state)
    sm.explore(find=is_good, avoid=is_bad)
    if sm.found:
        found_state = sm.found[0]
        password = found_state.solver.eval(pass1, cast_to=bytes).decode('utf-8')
        print('Solution: {}'.format(password))
    else:
        raise Exception("Solution not found")


if __name__ == '__main__':
    main()