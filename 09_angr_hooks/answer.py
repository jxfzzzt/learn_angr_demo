import angr
import claripy

def main():
    proj = angr.Project('09_angr_hooks')

    check_addr = 0x080486B3
    check_skip_size = 0x5

    init_state = proj.factory.entry_state()

    @proj.hook(check_addr, length=check_skip_size)
    def check_hook(state):
        user_input_addr = 0x0804A054
        user_input_size = 0x10
        user_input_bvs = state.memory.load(user_input_addr, size=user_input_size)

        desired_string = 'XYMKBKUHNIQYNQXE'

        state.regs.eax = claripy.If(
            desired_string == user_input_bvs,
            claripy.BVV(1, 32),
            claripy.BVV(0, 32)
        )


    def is_good(state):
        return b'Good Job' in state.posix.dumps(1)

    def is_bad(state):
        return b'Try again' in state.posix.dumps(1)

    sm = proj.factory.simulation_manager(init_state)
    sm.explore(find=is_good, avoid=is_bad)
    if sm.found:
        found_state = sm.found[0]
        password = found_state.posix.dumps(0).decode('utf-8')
        print('Solution: {}'.format(password)) # ZXIDRXEORJOTFFJNWUFAOUBLOGLQCCGK
    else:
        raise Exception('Solution not found')
if __name__ == '__main__':
    main()