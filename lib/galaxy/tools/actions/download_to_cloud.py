
import logging

from . import ToolAction
from json import dump, dumps

from galaxy.util.odict import odict

log = logging.getLogger(__name__)


class DownloadToCloudToolAction(ToolAction):
    def __init__(self):
        print '..> ' * 20

    def execute(self, tool, trans, history=None, incoming=None, completed_job=None, set_output_hid=True, execution_cache=None, dataset_collection_elements=None, rerun_remap_job_id=None):
        # history, rerun_remap_job_id, execution_cache, dataset_collection_elements, completed_job):
        # TODO: can think of a timer here -- take actions/upload.py/execute as an example.

        print '\n\n\n'
        import traceback
        for line in traceback.format_stack():
            print(line.strip())
        print '\n\n\n'

        print '...><' * 20
        print 'tool:\t', tool
        print 'trans:\t', trans
        print 'history:\t', history
        print 'incoming:\t', incoming
        print 'completed_job:\t', completed_job
        print 'execution_cache:\t', execution_cache
        print 'dataset_collection_elements:\t', dataset_collection_elements
        print 'rerun_remap_job_id:\t', rerun_remap_job_id
        print '\n_____________________'
        return self.create_job(trans, tool, history)

    def create_job(self, trans, tool, history, **kwargs): # params, tool, json_file_path, **kwargs): # outputs, folder=None, history=None, job_params=None, **kwargs):
        job = trans.app.model.Job()
        galaxy_session = trans.get_galaxy_session()
        if type(galaxy_session) == trans.model.GalaxySession:
            print '>' * 1000
            job.session_id = galaxy_session.id
        if trans.user is not None:
            job.user_id = trans.user.id
        print '-------------------------**********-------------- history: ', history
        job.history_id = history.id
        job.tool_id = tool.id
        job.tool_version = tool.version
        job.set_state(job.states.NEW)
        job.command_line = "python '/Users/vahid/Code/galaxy/improve_cloud_api/tools/data_source/download_to_cloud.py' AaA BbB CcC DdD EeE FfF"
        job.params = dumps({
            "provider": "aaaaaa",
            "access": "dlkfjs",
            "secret": "ccccc",
            "bucket": "lkjkl",
            "object": "qqqqq"
        })
        job.handler = trans.app.config.server_name
        trans.sa_session.add(job)
        trans.sa_session.flush()
        log.info('tool %s created job id %d' % (tool.id, job.id))
        trans.log_event('created job id %d' % job.id, tool_id=tool.id)
        # for name, value in tool.params_to_strings(params, trans.app).items():
        #     job.add_parameter(name, value)
        # job.add_parameter('paramfile', dumps(json_file_path))
        # job.set_state(job.states.NEW)
        # job.set_handler(tool.get_job_handler(None))
        # if job_params:
        #     for name, value in job_params.items():
        #         job.add_parameter(name, value)
        trans.app.job_manager.job_queue.put(job.id, job.tool_id)
        trans.log_event("Added job to the job queue, id: %s" % str(job.id), tool_id=job.tool_id)
        output = odict()
        print '===================== output:\t', output
        return job, output