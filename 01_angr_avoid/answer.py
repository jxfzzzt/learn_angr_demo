import angr

proj = angr.Project('./01_angr_avoid')

init_state = proj.factory.entry_state()
sm = proj.factory.simulation_manager(init_state)

sm.explore(find=0x080485E0, avoid=0x080485A8)  # 使用ida反编译

found_state = sm.found[0]
print(found_state.posix.dumps(0))
