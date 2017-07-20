define(["mvc/toolshed/toolshed-model","mvc/toolshed/util"],function(a,b){var c=Backbone.View.extend({el:"#center",defaults:[{}],initialize:function(){var b=this;this.model=new a.WorkflowTools,this.listenTo(this.model,"sync",this.render),this.model.fetch(),b.render()},render:function(){var a=this,c=a.templateWorkflows,d=a.model.models;a.$el.html(c({title:"Workflows Missing Tools",workflows:d,queue:b.queueLength()})),$("#center").css("overflow","auto"),a.bindEvents()},bindEvents:function(){var a=this;$(".show_wf_repo").on("click",function(){var a=$(this).attr("data-toolids"),b=$(this).attr("data-shed"),c=Galaxy.root+"api/tool_shed/repository",d={tool_ids:a};$.get(c,d,function(a){repository_id=a.repository.id;var c="repository/s/"+b.replace(/:/g,"%3a").replace(/\//g,"%2f")+"/r/"+a.repository.id;Backbone.history.navigate(c,{trigger:!0,replace:!0})})}),$(".queue_wf_repo").on("click",function(){var a=$(this),c=a.attr("data-toolids"),d=a.attr("data-shed"),e=Galaxy.root+"api/tool_shed/repository",f={tool_ids:c};$.get(e,f,function(c){repository_id=c.repository.id,f={tool_shed_url:d,repository_id:repository_id},$.get(e,f,function(c){var e=Object.keys(c.repository.metadata),f=e[0],g=c.repository.metadata[f];g.tool_shed_url=d,b.addToQueue(g),a.remove()})})}),$("#from_workflow").on("click",a.loadWorkflows)},reDraw:function(a){this.$el.empty(),this.initialize(a)},templateWorkflows:_.template(['<div class="unified-panel-header" id="panel_header" unselectable="on">','<div class="unified-panel-header-inner"><%= title %></div>','<div class="unified-panel-header-inner" style="position: absolute; right: 5px; top: 0px;"><a href="#/queue">Repository Queue (<%= queue %>)</a></div>',"</div>",'<style type="text/css">',".workflow_names, .workflow_tools { list-style-type: none; } ul.workflow_tools, ul.workflow_names {  padding-left: 0px; }","</style>",'<table id="workflows_missing_tools" class="grid" border="0" cellpadding="2" cellspacing="2" width="100%">','<thead id="grid-table-header">',"<tr>",'<th class="datasetRow">Workflows</th>','<th class="datasetRow">Tool IDs</th>','<th class="datasetRow">Shed</th>','<th class="datasetRow">Name</th>','<th class="datasetRow">Owner</th>','<th class="datasetRow">Actions</th>',"</tr>","</thead>","<tbody>","<% _.each(workflows, function(workflow) { %>","<tr>",'<td class="datasetRow">','<ul class="workflow_names">','<% _.each(workflow.get("workflows"), function(name) { %>','<li class="workflow_names"><%= name %></li>',"<% }); %>","</ul>","</td>",'<td class="datasetRow">','<ul class="workflow_tools">','<% _.each(workflow.get("tools"), function(tool) { %>','<li class="workflow_tools"><%= tool %></li>',"<% }); %>","</ul>","</td>",'<td class="datasetRow"><%= workflow.get("shed") %></td>','<td class="datasetRow"><%= workflow.get("repository") %></td>','<td class="datasetRow"><%= workflow.get("owner") %></td>','<td class="datasetRow">','<ul class="workflow_tools">','<li class="workflow_tools">','<input type="button" class="show_wf_repo btn btn-primary" data-shed="<%= workflow.get("shed") %>" data-owner="<%= workflow.get("owner") %>" data-repo="<%= workflow.get("repository") %>" data-toolids="<%= workflow.get("tools").join(",") %>" value="Show Repository" /></li>',"</ul>","</td>","</tr>","<% }); %>","</ul>","</div>"].join(""))});return{Workflows:c}});
//# sourceMappingURL=../../../maps/mvc/toolshed/workflows-view.js.map