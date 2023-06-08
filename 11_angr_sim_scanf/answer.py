import angr

def main():
    proj = angr.Project('11_angr_sim_scanf')

    init_state = proj.factory.entry_state()

    class MySimProcedure(angr.SimProcedure):
        def __init__(self):
            super(MySimProcedure, self).__init__()

        def run(self, format_string, scanf0_addr, scanf1_addr):
            scanf0 = init_state.solver.BVS('scanf0', 32)
            scanf1 = init_state.solver.BVS('scanf1', 32)

            self.state.memory.store(scanf0_addr, scanf0, endness=proj.arch.memory_endness)
            self.state.memory.store(scanf1_addr, scanf1, endness=proj.arch.memory_endness)

            self.state.globals['scanf0'] = scanf0
            self.state.globals['scanf1'] = scanf1

    scanf_symbol = '__isoc99_scanf'
    proj.hook_symbol(scanf_symbol, MySimProcedure())

    sm = proj.factory.simulation_manager(init_state)

    def is_good(state):
        return b'Good Job' in state.posix.dumps(1)
    def is_bad(state):
        return b'Try again' in state.posix.dumps(1)

    sm.explore(find=is_good, avoid=is_bad)

    if sm.found:
        found_state = sm.found[0]
        scanf0 = found_state.globals['scanf0']
        scanf1 = found_state.globals['scanf1']

        scanf0_input = found_state.solver.eval(scanf0)
        scanf1_input = found_state.solver.eval(scanf1)

        print('Solution: {} {}'.format(scanf0_input, scanf1_input)) # 1179604559 1146114388
    else:
        raise Exception('Solution not found')


if __name__ == '__main__':
    main()