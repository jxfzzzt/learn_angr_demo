import angr

def main():
    proj = angr.Project('12_angr_veritesting')

    init_state = proj.factory.entry_state()
    sm = proj.factory.simulation_manager(init_state, veritesting=True)

    def is_good(state):
        return b'Good Job' in state.posix.dumps(1)
    def is_bad(state):
        return b'Try again' in state.posix.dumps(1)

    sm.explore(find=is_good, avoid=is_bad)

    if sm.found:
        found_state = sm.found[0]
        password = found_state.posix.dumps(0).decode('utf-8')
        print('Solution: {}'.format(password))  # OQSUWYACEGIKMOQSUWYACEGIKMOQSUWY
    else:
        raise Exception("Solution not found")


if __name__ == '__main__':
    main()