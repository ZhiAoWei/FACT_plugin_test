import angr
import sys
from analysis.PluginBase import AnalysisBasePlugin


class AnalysisPlugin(AnalysisBasePlugin):
    NAME = 'angrr'
    DESCRIPTION = 'angr_first_test'
    DEPENDENCIES = []
    VERSION = '0.1.1'

    def __init__(self, plugin_adminstrator, config=None, recursive=True):
        self.config = config
        super().__init__(plugin_adminstrator, config=config, recursive=recursive, plugin_path=__file__)

    def process_object(self, file_object):
        # self-code
        result = ""
        path_to_binary = file_object.file_path
        project = angr.Project(path_to_binary, auto_load_libs=False)
        initial_state = project.factory.entry_state()
        simulation = project.factory.simgr(initial_state)
        target_address = 0x8048678
        simulation.explore(find=target_address)
        if simulation.found:
            solution_state = simulation.found[0]
            solution = solution_state.posix.dumps(sys.stdin.fileno())
            result = "{}".format(solution.decode("utf-8"))
        else:
            result = 'Could not find the solution'

        # store the results
        file_object.processed_analysis[self.NAME] = dict()
        file_object.processed_analysis[self.NAME]['angr_result'] = result

        # propagate some summary to parent objects
        file_object.processed_analysis[self.NAME]['summary'] = ['{} - {}'.format(result)]

        return file_object
