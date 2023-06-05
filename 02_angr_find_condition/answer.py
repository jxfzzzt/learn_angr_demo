import angr


def main():
    proj = angr.Project('./02_angr_find_condition')
    init_state = proj.factory.entry_state()
    sm = proj.factory.simulation_manager(init_state)

    def is_good(state):
        return b'Good Job' in state.posix.dumps(1)

    def is_bad(state):
        return b'Try again' in state.posix.dumps(1)

    sm.explore(find=is_good, avoid=is_bad)

    if sm.found:
        found_state = sm.found[0]
        print('Solution is {}'.format(found_state.posix.dumps(0)))
    else:
        raise Exception("Solution not found")

if __name__ == '__main__':
    main()
