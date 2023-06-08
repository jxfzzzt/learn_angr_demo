import angr

def main():
    proj = angr.Project('13_angr_static_binary') # 静态链接，导致出现路径爆炸的问题

    printf_addr = 0x0804ED40
    strcmp_addr = 0x08048280
    puts_addr = 0x0804F350
    scanf_addr = 0x0804ED80
    libc_start_main_addr = 0x08048D10

    init_state = proj.factory.entry_state()
    proj.hook(printf_addr, angr.SIM_PROCEDURES['libc']['printf']())
    proj.hook(strcmp_addr, angr.SIM_PROCEDURES['libc']['strcmp']())
    proj.hook(puts_addr, angr.SIM_PROCEDURES['libc']['puts']())
    proj.hook(scanf_addr, angr.SIM_PROCEDURES['libc']['scanf']())
    proj.hook(libc_start_main_addr, angr.SIM_PROCEDURES['glibc']['__libc_start_main']())

    def is_good(state):
        return b'Good Job' in state.posix.dumps(1)

    def is_bad(state):
        return b'Try again' in state.posix.dumps(1)

    sm = proj.factory.simulation_manager(init_state)
    sm.explore(find=is_good, avoid=is_bad)

    if sm.found:
        found_state = sm.found[0]
        password = found_state.posix.dumps(0).decode('utf-8')
        print('Solution: {}'.format(password)) # PNMXNMUD
    else:
        raise Exception('Solution not found')


if __name__ == '__main__':
    main()