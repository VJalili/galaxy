define("mvc/history/history-structure-view", ["exports", "mvc/history/job-dag", "mvc/job/job-model", "mvc/job/job-li", "mvc/dataset/dataset-li", "mvc/base-mvc", "utils/localization", "libs/d3"], function(exports, _jobDag, _jobModel, _jobLi, _datasetLi, _baseMvc, _localization) {
    "use strict";

    Object.defineProperty(exports, "__esModule", {
        value: true
    });

    var _jobDag2 = _interopRequireDefault(_jobDag);

    var _jobModel2 = _interopRequireDefault(_jobModel);

    var _jobLi2 = _interopRequireDefault(_jobLi);

    var _datasetLi2 = _interopRequireDefault(_datasetLi);

    var _baseMvc2 = _interopRequireDefault(_baseMvc);

    var _localization2 = _interopRequireDefault(_localization);

    function _interopRequireDefault(obj) {
        return obj && obj.__esModule ? obj : {
            default: obj
        };
    }

    var logNamespace = "history";
    // ============================================================================
    /*
    TODO:
        disruptive:
            handle collections
            retain contents to job relationships (out/input name)
    
        display when *only* copied datasets
            need to change when/how joblessVertices are created
    
        components should be full height containers that scroll individually
    
        use history contents views for job outputCollection, not vanilla datasets
             need hid
    
        show datasets when job not expanded
            make them external to the job display
        connect jobs by dataset
            which datasets from job X are which inputs in job Y?
    
        make job data human readable (needs tool data)
            show only tool.inputs with labels (w/ job.params as values)
            input datasets are special
                they don't appear in job.params
                have to connect to datasets in the dag
                    connect job.inputs to any tool.inputs by tool.input.name (in params)
    
    API: seems like this could be handled there - duplicating the input data in the proper param space
    
        collections
    
        use cases:
            operations by thread:
                copy to new history
                rerun
                to workflow
            operations by branch (all descendants):
                copy to new history
                rerun
                to workflow
            signal to noise:
                collapse/expand branch
                hide jobs
                visually isolate branch (hide other jobs) of thread
                zoom (somehow)
    
                layout changes:
                    move branch to new column in component
                        complicated
                    pyramid
                    circular
                        sources on inner radius
                expansion in vertical:
                    obscures relations due to height
                        could move details to side panel
                    difficult to compare two+ jobs/datasets when at different points in the topo
    
        (other) controls:
            (optionally) filter all deleted
            (optionally) filter all hidden
            //(optionally) filter __SET_METADATA__
            //(optionally) filter error'd jobs
            help and explanation
            filtering/searching of jobs
    
        challenges:
            difficult to scale dom (for zoomout)
                possible to use css transforms?
                    transform svg and dom elements
                    it is possible to use css transforms on svg nodes
                    use transform-origin to select origin to top left
            on larger histories the svg section may become extremely large due to distance from output to input
    
        how-to:
            descendant ids: _.keys( component.depth/breadthFirstSearchTree( start ).vertices )
    
        in-panel view of anc desc
    
    
    */
    // ============================================================================
    /**
     *
     */
    window.JobDAG = _jobDag2.default;
    var HistoryStructureComponent = Backbone.View.extend(_baseMvc2.default.LoggableMixin).extend({
        _logNamespace: logNamespace,

        className: "history-structure-component",

        _INITIAL_ZOOM_LEVEL: 1.0,
        _MIN_ZOOM_LEVEL: 0.25,
        _LINK_ID_SEP: "-to-",
        _VERTEX_NAME_DATA_KEY: "vertex-name",

        JobItemClass: _jobLi2.default.JobListItemView,
        ContentItemClass: _datasetLi2.default.DatasetListItemView,

        initialize: function initialize(attributes) {
            this.log(this + "(HistoryStructureComponent).initialize:", attributes);
            this.component = attributes.component;

            this._liMap = {};
            this._createVertexItems();
            this.zoomLevel = attributes.zoomLevel || this._INITIAL_ZOOM_LEVEL;

            this.layout = this._createLayout(attributes.layoutOptions);
        },

        _createVertexItems: function _createVertexItems() {
            var view = this;
            view.component.eachVertex(function(vertex) {
                //TODO: hack
                var type = vertex.data.job ? "job" : "copy";

                var li;
                if (type === "job") {
                    li = view._createJobListItem(vertex);
                } else if (type === "copy") {
                    li = view._createContentListItem(vertex);
                }
                view._liMap[vertex.name] = li;
            });
            view.debug("_liMap:", view._liMap);
        },

        _createJobListItem: function _createJobListItem(vertex) {
            this.debug("_createJobListItem:", vertex);
            var view = this;
            var jobData = vertex.data;
            var job = new _jobModel2.default.Job(jobData.job);

            // get the models of the outputs for this job from the history
            var outputModels = _.map(job.get("outputs"), function(output //note: output is { src: 'hda/dataset_collection', id: <some id> }
            ) {
                return (
                    // job output doesn't *quite* match up to normal typeId
                    view.model.contents.get(output.type_id)
                );
            });
            // set the collection (HistoryContents) for the job to that json (setting historyId for proper ajax urls)
            job.outputCollection.reset(outputModels);
            job.outputCollection.historyId = view.model.id;
            //this.debug( job.outputCollection );

            // create the bbone view for the job (to be positioned later accrd. to the layout) and cache
            var li = new view.JobItemClass({
                model: job,
                tool: jobData.tool,
                jobData: jobData
            });
            view.listenTo(li, "expanding expanded collapsing collapsed", view.renderGraph);
            view.listenTo(li.foldout, "view:expanding view:expanded view:collapsing view:collapsed", view.renderGraph);
            return li;
        },

        _createContentListItem: function _createContentListItem(vertex) {
            this.debug("_createContentListItem:", vertex);
            var view = this;
            var content = vertex.data;
            content = view.model.contents.get(content.type_id);
            var li = new view.ContentItemClass({
                model: content
            });
            view.listenTo(li, "expanding expanded collapsing collapsed", view.renderGraph);
            return li;
        },

        layoutDefaults: {
            linkSpacing: 16,
            linkWidth: 0,
            linkHeight: 0,
            jobWidth: 300,
            jobHeight: 300,
            jobSpacing: 12,
            linkAdjX: 4,
            linkAdjY: 0
        },

        _createLayout: function _createLayout(options) {
            options = _.defaults(_.clone(options || {}), this.layoutDefaults);
            var view = this;
            var vertices = _.values(view.component.vertices);

            var layout = _.extend(options, {
                nodeMap: {},
                links: [],
                svg: {
                    width: 0,
                    height: 0
                }
            });

            vertices.forEach(function(v, j) {
                var node = {
                    name: v.name,
                    x: 0,
                    y: 0
                };
                layout.nodeMap[v.name] = node;
            });

            view.component.edges(function(e) {
                var link = {
                    source: e.source,
                    target: e.target
                };
                layout.links.push(link);
            });
            //this.debug( JSON.stringify( layout, null, '  ' ) );
            return layout;
        },

        render: function render(options) {
            this.debug(this + ".render:", options);
            var view = this;
            view.$el.html(["<header></header>", '<nav class="controls"></nav>', '<figure class="graph"></figure>', "<footer></footer>"].join(""));

            var $graph = view.$graph();
            view.component.eachVertex(function(vertex) {
                view._liMap[vertex.name].render(0).$el.appendTo($graph)
                    // store the name in the DOM and cache by that name
                    .data(view._VERTEX_NAME_DATA_KEY, vertex.name);
            });
            view.renderGraph();
            return this;
        },

        $graph: function $graph() {
            return this.$(".graph");
        },

        renderGraph: function renderGraph(options) {
            this.debug(this + ".renderGraph:", options);
            var view = this;

            function _render() {
                view._updateLayout();
                // set up the display containers
                view.$graph()
                    // use css3 transform to scale component graph
                    .css("transform", ["scale(", view.zoomLevel, ",", view.zoomLevel, ")"].join("")).width(view.layout.svg.width).height(view.layout.svg.height);
                view.renderSVG();

                // position the job views accrd. to the layout
                view.component.eachVertex(function(v) {
                    //TODO:?? liMap needed - can't we attach to vertex?
                    var li = view._liMap[v.name];

                    var position = view.layout.nodeMap[v.name];
                    //this.debug( position );
                    li.$el.css({
                        top: position.y,
                        left: position.x
                    });
                });
            }
            //TODO: hack - li's invisible in updateLayout without this delay
            if (!this.$el.is(":visible")) {
                _.delay(_render, 0);
            } else {
                _render();
            }
            return this;
        },

        _updateLayout: function _updateLayout() {
            this.debug(this + "._updateLayout:");
            var view = this;
            var layout = view.layout;

            layout.linkHeight = layout.linkSpacing * _.size(layout.nodeMap);
            layout.svg.height = layout.linkHeight + layout.jobHeight;

            // reset for later max comparison
            layout.svg.width = 0;

            //TODO:?? can't we just alter the component v and e's directly?
            // layout the job views putting jobSpacing btwn each
            var x = 0;

            var y = layout.linkHeight;
            _.each(layout.nodeMap, function(node, jobId) {
                //this.debug( node, jobId );
                node.x = x;
                node.y = y;
                x += layout.jobWidth + layout.jobSpacing;
            });
            layout.svg.width = layout.linkWidth = Math.max(layout.svg.width, x);

            // layout the links - connecting each job by it's main coords (currently)
            //TODO: somehow adjust the svg height based on the largest distance the longest connection needs
            layout.links.forEach(function(link) {
                var source = layout.nodeMap[link.source];
                var target = layout.nodeMap[link.target];
                link.x1 = source.x + layout.linkAdjX;
                link.y1 = source.y + layout.linkAdjY;
                link.x2 = target.x + layout.linkAdjX;
                link.y2 = target.y + layout.linkAdjY;
            });

            this.debug(JSON.stringify(layout, null, "  "));
            return this.layout;
        },

        renderSVG: function renderSVG() {
            this.debug(this + ".renderSVG:");
            var view = this;
            var layout = view.layout;

            var svg = d3.select(this.$graph().get(0)).select("svg");
            if (svg.empty()) {
                svg = d3.select(this.$graph().get(0)).append("svg");
            }

            svg.attr("width", layout.svg.width).attr("height", layout.svg.height);

            function highlightConnect(d) {
                d3.select(this).classed("highlighted", true);
                view._liMap[d.source].$el.addClass("highlighted");
                view._liMap[d.target].$el.addClass("highlighted");
            }

            function unhighlightConnect(d) {
                d3.select(this).classed("highlighted", false);
                view._liMap[d.source].$el.removeClass("highlighted");
                view._liMap[d.target].$el.removeClass("highlighted");
            }

            var connections = svg.selectAll(".connection").data(layout.links);

            connections.enter().append("path").attr("class", "connection").attr("id", function(d) {
                return [d.source, d.target].join(view._LINK_ID_SEP);
            }).on("mouseover", highlightConnect).on("mouseout", unhighlightConnect);

            connections.attr("d", function(d) {
                return view._connectionPath(d);
            });

            return svg.node();
        },

        _connectionPath: function _connectionPath(d) {
            var CURVE_X = 0;

            var controlY = (d.x2 - d.x1) / this.layout.svg.width * this.layout.linkHeight;

            return ["M", d.x1, ",", d.y1, " ", "C", d.x1 + CURVE_X, ",", d.y1 - controlY, " ", d.x2 - CURVE_X, ",", d.y2 - controlY, " ", d.x2, ",", d.y2].join("");
        },

        events: {
            "mouseover .graph > .list-item": function mouseoverGraphListItem(ev) {
                this.highlightConnected(ev.currentTarget, true);
            },
            "mouseout  .graph > .list-item": function mouseoutGraphListItem(ev) {
                this.highlightConnected(ev.currentTarget, false);
            }
        },

        highlightConnected: function highlightConnected(jobElement, highlight) {
            this.debug("highlightConnected", jobElement, highlight);
            highlight = highlight !== undefined ? highlight : true;

            var view = this;
            var component = view.component;

            var jobClassFn = highlight ? jQuery.prototype.addClass : jQuery.prototype.removeClass;

            var connectionClass = highlight ? "connection highlighted" : "connection";

            //console.debug( 'mouseover', this );
            var $hoverTarget = jobClassFn.call($(jobElement), "highlighted");

            var id = $hoverTarget.data(view._VERTEX_NAME_DATA_KEY);

            // immed. ancestors
            component.edges({
                target: id
            }).forEach(function(edge) {
                var ancestorId = edge.source;
                var ancestorLi = view._liMap[ancestorId];
                //view.debug( '\t ancestor:', ancestorId, ancestorLi );
                jobClassFn.call(ancestorLi.$el, "highlighted");
                view.$("#" + ancestorId + view._LINK_ID_SEP + id).attr("class", connectionClass);
            });
            // descendants
            component.vertices[id].eachEdge(function(edge) {
                var descendantId = edge.target;
                var descendantLi = view._liMap[descendantId];
                //view.debug( '\t descendant:', descendantId, descendantLi );
                jobClassFn.call(descendantLi.$el, "highlighted");
                view.$("#" + id + view._LINK_ID_SEP + descendantId).attr("class", connectionClass);
            });
        },

        zoom: function zoom(level) {
            this.zoomLevel = Math.min(1.0, Math.max(this._MIN_ZOOM_LEVEL, level));
            return this.renderGraph();
        },

        toString: function toString() {
            return "HistoryStructureComponent(" + this.model.id + ")";
        }
    });

    // ============================================================================
    /**
     *
     */
    var VerticalHistoryStructureComponent = HistoryStructureComponent.extend({
        //logger : console,

        className: HistoryStructureComponent.prototype.className + " vertical",

        layoutDefaults: _.extend(_.clone(HistoryStructureComponent.prototype.layoutDefaults), {
            linkAdjX: 0,
            linkAdjY: 4
        }),

        //TODO: how can we use the dom height of the job li's - they're not visible when this is called?
        _updateLayout: function _updateLayout() {
            this.debug(this + "._updateLayout:");
            var view = this;
            var layout = view.layout;
            //this.info( this.cid, '_updateLayout' )

            layout.linkWidth = layout.linkSpacing * _.size(layout.nodeMap);
            layout.svg.width = layout.linkWidth + layout.jobWidth;

            // reset height - we'll get the max Y below to assign to it
            layout.svg.height = 0;

            //TODO:?? can't we just alter the component v and e's directly?
            var x = layout.linkWidth;

            var y = 0;
            _.each(layout.nodeMap, function(node, nodeId) {
                node.x = x;
                node.y = y;
                var li = view._liMap[nodeId];
                y += li.$el.height() + layout.jobSpacing;
            });
            layout.linkHeight = layout.svg.height = Math.max(layout.svg.height, y);

            // layout the links - connecting each job by it's main coords (currently)
            layout.links.forEach(function(link) {
                var source = layout.nodeMap[link.source];
                var target = layout.nodeMap[link.target];
                link.x1 = source.x + layout.linkAdjX;
                link.y1 = source.y + layout.linkAdjY;
                link.x2 = target.x + layout.linkAdjX;
                link.y2 = target.y + layout.linkAdjY;
                //view.debug( 'link:', link.x1, link.y1, link.x2, link.y2, link );
            });

            this.debug(JSON.stringify(layout, null, "  "));
            return layout;
        },

        _connectionPath: function _connectionPath(d) {
            var CURVE_Y = 0;

            var controlX = (d.y2 - d.y1) / this.layout.svg.height * this.layout.linkWidth;

            return ["M", d.x1, ",", d.y1, " ", "C", d.x1 - controlX, ",", d.y1 + CURVE_Y, " ", d.x2 - controlX, ",", d.y2 - CURVE_Y, " ", d.x2, ",", d.y2].join("");
        },

        toString: function toString() {
            return "VerticalHistoryStructureComponent(" + this.model.id + ")";
        }
    });

    // ============================================================================
    /**
     *
     */
    var HistoryStructureView = Backbone.View.extend(_baseMvc2.default.LoggableMixin).extend({
        _logNamespace: logNamespace,

        className: "history-structure",

        _layoutToComponentClass: {
            horizontal: HistoryStructureComponent,
            vertical: VerticalHistoryStructureComponent
        },
        //_DEFAULT_LAYOUT : 'horizontal',
        _DEFAULT_LAYOUT: "vertical",

        initialize: function initialize(attributes) {
            this.layout = _.contains(attributes.layout, _.keys(this._layoutToComponentClass)) ? attributes.layout : this._DEFAULT_LAYOUT;
            this.log(this + "(HistoryStructureView).initialize:", attributes, this.model);
            //TODO:?? to model - maybe glom jobs onto model in order to persist
            // cache jobs since we need to re-create the DAG if settings change
            this._processTools(attributes.tools);
            this._processJobs(attributes.jobs);
            this._createDAG();
        },

        _processTools: function _processTools(tools) {
            this.tools = tools || {};
            return this.tools;
        },

        _processJobs: function _processJobs(jobs) {
            this.jobs = jobs || [];
            return this.jobs;
        },

        _createDAG: function _createDAG() {
            this.dag = new _jobDag2.default({
                historyContents: this.model.contents.toJSON(),
                tools: this.tools,
                jobs: this.jobs,
                excludeSetMetadata: true,
                excludeErroredJobs: true
            });
            this.debug(this + ".dag:", this.dag);
            this._createComponents();
        },

        _createComponents: function _createComponents() {
            this.log(this + "._createComponents");
            var structure = this;

            structure.componentViews = structure.dag.weakComponentGraphArray().map(function(componentGraph) {
                return structure._createComponent(componentGraph);
            });
            return structure.componentViews;
        },

        _createComponent: function _createComponent(component) {
            this.log(this + "._createComponent:", component);
            var ComponentClass = this._layoutToComponentClass[this.layout];
            return new ComponentClass({
                model: this.model,
                component: component
            });
        },

        render: function render(options) {
            this.log(this + ".render:", options);
            var structure = this;

            structure.$el.addClass("clear").html(['<div class="controls"></div>', '<div class="components"></div>'].join(""));

            structure.componentViews.forEach(function(component) {
                component.render().$el.appendTo(structure.$components());
            });
            return structure;
        },

        $components: function $components() {
            return this.$(".components");
        },

        changeLayout: function changeLayout(layout) {
            if (!(layout in this._layoutToComponentClass)) {
                throw new Error(this + ": unknown layout: " + layout);
            }
            this.layout = layout;
            this._createComponents();
            return this.render();
        },

        toString: function toString() {
            return "HistoryStructureView(" + this.model.id + ")";
        }
    });

    // ============================================================================
    exports.default = HistoryStructureView;
});
//# sourceMappingURL=../../../maps/mvc/history/history-structure-view.js.map
