import angr

def main():
    proj = angr.Project('00_angr_find')

    init_state = proj.factory.entry_state()

    sm = proj.factory.simulation_manager(init_state)
    sm.explore(find=0x08048678)  # 该地址通过ida工具得到

    if sm.found:
        found_state = sm.found[0]  # 找到一个满足条件的输入
        password = found_state.posix.dumps(0).decode('utf-8')
        print('Solution: {}'.format(password))  # 输出JXWVXRKX
    else:
        raise Exception("Solution not found")

if __name__ == '__main__':
    main()