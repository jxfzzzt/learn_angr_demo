import angr


def main():
    proj = angr.Project('08_angr_constraints')
    start_addr = 0x08048625

    init_state = proj.factory.blank_state(addr=start_addr)

    s_size = 0x10
    buffer_addr = 0x0804A050
    check_addr = 0x08048565

    pass1 = init_state.solver.BVS('pass1', s_size * 8)
    init_state.memory.store(buffer_addr, pass1)

    sm = proj.factory.simulation_manager(init_state)
    sm.explore(find=check_addr)

    if sm.found:
        check_state = sm.found[0]
        desired_string = 'AUPDNNPROEZRJWKB'

        check_param1 = buffer_addr
        check_param2 = 0x10

        check_bvs = check_state.memory.load(check_param1, check_param2)

        check_constraint = check_bvs == desired_string
        check_state.add_constraints(check_constraint)

        password = check_state.solver.eval(pass1, cast_to=bytes).decode('utf-8')
        print('Solution: {}'.format(password)) # LGCRCDGJHYUNGUJB
    else:
        raise Exception("Solution not found")


if __name__ == '__main__':
    main()