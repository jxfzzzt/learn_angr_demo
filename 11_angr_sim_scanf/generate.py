#!/usr/bin/env python3
import sys, random, os, tempfile, jinja2

def generate_true_statement(variable, value):
  random_int = random.randint(0, 0xFFFFFFFF)
  value_xor_int = value ^ random_int
  return '(!(' + variable + ' ^ ' + str(random_int) + ' ^ ' + str(value_xor_int) + '))'

def recursive_if_else(variable, value, end_statement, depth):
  if depth == 0:
    return end_statement
  else:
    if_true = random.choice([True, False])
    if (if_true):
      ret_str = 'if (' + generate_true_statement(variable, value) + ') {' + recursive_if_else(variable, value, end_statement, depth - 1) + '} else {' + recursive_if_else(variable, value, end_statement, depth - 1) + '}'
    else:
      ret_str = 'if (!' + generate_true_statement(variable, value) + ') {' + recursive_if_else(variable, value, end_statement, depth - 1) + '} else {' + recursive_if_else(variable, value, end_statement, depth - 1) + '}'
    return ret_str

def generate(argv):
  if len(argv) != 3:
    print('Usage: ./generate.py [seed] [output_file]')
    sys.exit()

  seed = argv[1]
  output_file = argv[2]
  random.seed(seed)

  userdef_charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
  userdef = ''.join(random.choice(userdef_charset) for _ in range(8))
  padding0 = random.randint(0, 2**16)
  padding1 = random.randint(0, 2**16)
  padding2 = random.randint(0, 2**16)

  statement = """
    scanf("%u %u", (uint32_t*) buffer0, (uint32_t*) buffer1);
    keep_going = keep_going && !strncmp(buffer0, &password[0], 4) && !strncmp(buffer1, &password[4], 4);
  """
  recursive_if_else_string = recursive_if_else('x', 0xDEADBEEF, statement, 8)

  template = open(os.path.join(os.path.dirname(os.path.realpath(__file__)), '11_angr_sim_scanf.c.jinja'), 'r').read()
  t = jinja2.Template(template)
  c_code = t.render(description='', userdef=userdef, len_userdef=len(userdef), padding0=padding0, padding1=padding1, padding2=padding2, recursive_if_else=recursive_if_else_string)
  print(c_code)

  with tempfile.NamedTemporaryFile(delete=False, suffix='.c', mode='w') as temp:
    temp.write(c_code)
    temp.seek(0)
    os.system('gcc -fno-pie -no-pie -m32 -o ' + output_file + ' ' + temp.name)

if __name__ == '__main__':
  generate(sys.argv)
