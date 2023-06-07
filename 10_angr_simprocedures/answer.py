import angr
import claripy


def main():
    proj = angr.Project("10_angr_simprocedures")

    init_state = proj.factory.entry_state()

    check_symbol = 'check_equals_ORSDDWXHZURJRBDH'

    class MySimProcedure(angr.SimProcedure):
        def __init__(self):
            super(MySimProcedure, self).__init__()

        def run(self, user_input_addr, user_input_size):
            user_input_bvs = self.state.memory.load(user_input_addr, size=user_input_size)

            desired_string = 'ORSDDWXHZURJRBDH'

            return claripy.If(
                user_input_bvs == desired_string,
                claripy.BVV(1, 32),
                claripy.BVV(0, 32)
            )


    proj.hook_symbol(check_symbol, MySimProcedure())

    def is_good(state):
        return b'Good Job' in state.posix.dumps(1)
    def is_bad(state):
        return b'Try again' in state.posix.dumps(1)

    sm = proj.factory.simulation_manager(init_state)
    sm.explore(find=is_good, avoid=is_bad)

    if sm.found:
        found_state = sm.found[0]
        password = found_state.posix.dumps(0).decode('utf-8')
        print('Solution: {}'.format(password)) # MSWKNJNAVTTOZMRY
    else:
        raise Exception("Solution not found")

if __name__ == '__main__':
    main()