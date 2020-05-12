from cmd import Cmd
import json
import logging
from msf.lib.discovery import Discovery
from msf.lib.exploit import ExploitLoader, Revshell
import os
from typing import List


class MSFMenu(Cmd):
    """
    Interactive command shell for MSFPY.
    """

    prompt = 'msfpy> '
    intro = '\n##### WELCOME TO MSFPY #####\n'
    valid_vars = sorted(('target', 'port', 'ports', 'revshell_ip', 'revshell_port'))
    discover_args = sorted(('print', 'show', 'get'))
    module_args = sorted(('list', 'describe', 'use'))

    def __init__(self, exploits):
        super().__init__()
        self.all_vars = {}
        self.all_results = {}
        self.current_exploit_name = None
        self.current_exploit = None
        self.exploits = exploits

    def print_possible_vars(self):
        """
        Print out all valid variables that can be set.
        :return: None
        """
        print('Possible variables: {}'.format(self.valid_vars))
        return False

    def check_possible_vars(self, inp: str):
        """
        Sanitize input string, then check to make sure the input string is a valid variable name.
        :param inp: input string
        :return: sanitized input string on success, False otherwise
        """
        if not inp:
            return False
        inp = inp.strip().lower()
        if inp not in self.valid_vars:
            print('Error, {} is not set or is not a valid variable.'.format(inp))
            return self.print_possible_vars()
        return inp

    @staticmethod
    def get_completion(valid_options: List, text: str, line, begidx, endidx) -> List:
        """
        Build completion List based on given List of valid options.
        :param valid_options: List of valid options
        :param text: current input string
        :param line: line number
        :param begidx: beginning index
        :param endidx: ending index
        :return: List of possible completions
        """
        if not text:
            return valid_options
        return [v for v in valid_options if v.startswith(text)]

    def do_exit(self, inp):
        print('Bye!')
        return True

    def do_shell(self, inp):
        os.system(inp)

    def help_shell(self):
        print('Execute arbitrary shell commands')
        print('Usage:  shell <command>')

    def do_get(self, inp):
        if not inp:
            print(self.all_vars)
            return False
        inp = self.check_possible_vars(inp)
        if inp and inp in self.all_vars:
            print(self.all_vars[inp])

    def help_get(self):
        print('Get the value of a defined variable.')
        print('Usage:  get [variable_name]')

    def complete_get(self, text, line, begidx, endidx):
        return self.complete_set(text, line, begidx, endidx)

    def do_set(self, inp):
        if not inp:
            return self.print_possible_vars()
        splitter = inp.split()
        if len(splitter) < 2:
            print('Error, you must specify a key and value.')
            return False
        splitter[0] = self.check_possible_vars(splitter[0])
        if splitter[0]:
            self.all_vars[splitter[0]] = splitter[1]

    def help_set(self):
        print('Set the value of a variable, or list valid variables if nothing specified after set.')
        print('Usage:  set [variable_name] [variable_value]')

    def complete_set(self, text, line, begidx, endidx):
        return MSFMenu.get_completion(self.valid_vars, text, line, begidx, endidx)

    def do_unset(self, inp):
        inp = self.check_possible_vars(inp)
        if inp:
            del self.all_vars[inp]

    def help_unset(self):
        print('Unset the value of a variable.')
        print('Usage:  unset [variable_name]')

    def complete_unset(self, text, line, begidx, endidx):
        return self.complete_set(text, line, begidx, endidx)

    def do_write_results(self, inp):
        if not inp:
            print('Error, you must specify a valid file path to write to.')
            return False
        inp = inp.strip()
        with open(inp, 'w') as of:
            json.dump(self.all_results, of, indent=2)
        print('Finished writing results to {}.'.format(inp))

    def help_write_results(self):
        print('Write results of discovery scan to a JSON file.')
        print('Usage:  write_results <output_file>')

    def do_discover(self, inp):
        if inp:
            inp = inp.strip().lower()
            if inp in self.discover_args:
                print(self.all_results['discover'][self.all_vars['target']])
            else:
                print('Error, invalid argument specified.')
            return False
        if 'target' not in self.all_vars:
            print('Error, no target defined. Set target first with "set target <target>".')
            return False
        discovery = Discovery()
        if 'ports' in self.all_vars:
            print('Starting discovery on host {} on ports {}.'.format(self.all_vars['target'], self.all_vars['ports']))
            port_results, os_results = discovery.do_discovery(self.all_vars['target'], ports=self.all_vars['ports'],
                                                              sudo=True)
        else:
            print('Starting discovery on host {} on all ports.'.format(self.all_vars['target']))
            port_results, os_results = discovery.do_discovery(self.all_vars['target'], sudo=True)
        self.all_results['discover'] = {self.all_vars['target']: (port_results, os_results)}
        print('Done. Results stored in memory.')

    def help_discover(self):
        print('Perform service discovery against target host.')

    def complete_discover(self, text, line, begidx, endidx):
        return MSFMenu.get_completion(self.discover_args, text, line, begidx, endidx)

    def do_module(self, inp):
        if not inp:
            return False
        splitter = inp.split()
        splitter[0] = splitter[0].lower()
        if splitter[0] not in self.module_args:
            print('Error, {} is not set or is not a valid module operation.'.format(splitter[0]))
            print('Possible module operations: {}'.format(self.module_args))
            return False
        if splitter[0] == 'use':
            # TODO: prepare module
            if splitter[1] not in self.exploits:
                pass
            self.current_exploit = self.exploits[splitter[1]]
            self.current_exploit_name = splitter[1]
            self.prompt = '({}) msfpy> '.format(self.current_exploit_name)
        elif splitter[0] == 'describe':
            if self.current_exploit:
                self.current_exploit.describe()
        elif splitter[0] == 'list':
            print('Available exploits: {}'.format(sorted(self.exploits.keys())))

    def help_module(self):
        print('Look for and select available exploits.')
        print('Usage:  module <list|describe|use [module]>')

    def complete_module(self, text, line, begidx, endidx):
        return MSFMenu.get_completion(self.module_args, text, line, begidx, endidx)

    def do_exploit(self, inp):
        if not self.current_exploit:
            print('Error, no exploit currently defined.')
            return False
        if 'target' not in self.all_vars:
            print('Error, no target currently defined.')
            return False
        if 'revshell_ip' not in self.all_vars:
            self.all_vars['revshell_ip'] = Revshell.DEFAULT_REVSHELL_IP
        if 'revshell_port' not in self.all_vars:
            self.all_vars['revshell_port'] = Revshell.DEFAULT_REVSHELL_PORT
        if 'port' in self.all_vars:
            revshell = self.current_exploit.exploit(self.all_vars['target'], self.all_vars['port'],
                                                    self.all_vars['revshell_ip'], self.all_vars['revshell_port'])
        else:
            revshell = self.current_exploit.exploit(self.all_vars['target'], revshell_ip=self.all_vars['revshell_ip'],
                                                    revshell_port=self.all_vars['revshell_port'])
        if revshell:
            revshell.interact()
        else:
            print('Error, exploit did not complete successfully.')

    def help_exploit(self):
        print('Attempt to execute selected exploit against target.')

    def do_check(self, inp):
        if not self.current_exploit:
            print('Error, no exploit currently defined.')
            return False
        if 'target' not in self.all_vars:
            print('Error, no target currently defined.')
            return False
        if 'port' in self.all_vars:
            self.current_exploit.check(self.all_vars['target'], self.all_vars['port'])
        else:
            self.current_exploit.check(self.all_vars['target'])

    def help_check(self):
        print('Check if target is vulnerable to selected exploit.')


def main():
    logging.basicConfig(level=logging.INFO, format='%(asctime)s | %(levelname)s | %(message)s')
    print('\nLoading exploits...')
    exploits = ExploitLoader.load_exploits()
    MSFMenu(exploits).cmdloop()


if __name__ == '__main__':
    main()
