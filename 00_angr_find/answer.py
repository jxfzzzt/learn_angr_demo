import angr

proj = angr.Project('./00_angr_find')
init_state = proj.factory.entry_state()
sm = proj.factory.simulation_manager(init_state)

sm.explore(find=0x08048678)  # 该地址通过ida工具得到

found_state = sm.found[0]  # 找到一个满足条件的输入

print(found_state.posix.dumps(0))  # 输出JXWVXRKX
