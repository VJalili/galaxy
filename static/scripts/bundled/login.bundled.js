webpackJsonp([3],{

/***/ 152:
/*!**************************************!*\
  !*** ./galaxy/scripts/apps/login.js ***!
  \**************************************/
/*! dynamic exports provided */
/*! all exports used */
/***/ (function(module, exports, __webpack_require__) {

"use strict";
eval("/* WEBPACK VAR INJECTION */(function(Backbone, _) {\n\nvar _jquery = __webpack_require__(/*! jquery */ 0);\n\nvar _jquery2 = _interopRequireDefault(_jquery);\n\nvar _galaxy = __webpack_require__(/*! galaxy */ 65);\n\nvar _galaxy2 = _interopRequireDefault(_galaxy);\n\nvar _localization = __webpack_require__(/*! utils/localization */ 3);\n\nvar _localization2 = _interopRequireDefault(_localization);\n\nvar _page = __webpack_require__(/*! layout/page */ 43);\n\nvar _page2 = _interopRequireDefault(_page);\n\nfunction _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }\n\nvar $ = _jquery2.default;\n\n\nwindow.app = function app(options, bootstrapped) {\n    window.Galaxy = new _galaxy2.default.GalaxyApp(options, bootstrapped);\n    Galaxy.debug(\"login app\");\n    var redirect = encodeURI(options.redirect);\n\n    // TODO: remove iframe for user login (at least) and render login page from here\n    // then remove this redirect\n    if (!options.show_welcome_with_login) {\n        var params = _jquery2.default.param({ use_panels: \"True\", redirect: redirect });\n        window.location.href = Galaxy.root + \"user/login?\" + params;\n        return;\n    }\n\n    var LoginPage = Backbone.View.extend({\n        initialize: function initialize(page) {\n            this.page = page;\n            this.model = new Backbone.Model({ title: (0, _localization2.default)(\"Login required\") });\n            this.setElement(this._template());\n        },\n        render: function render() {\n            this.page.$(\"#galaxy_main\").prop(\"src\", options.welcome_url);\n        },\n        _template: function _template() {\n            var login_url = options.root + \"user/login?\" + $.param({\n                redirect: redirect\n            });\n            return \"<iframe src=\\\"\" + login_url + \"\\\" frameborder=\\\"0\\\" style=\\\"width: 100%; height: 100%;\\\"/>\";\n        }\n    });\n\n    $(function () {\n        Galaxy.page = new _page2.default.View(_.extend(options, {\n            Right: LoginPage\n        }));\n    });\n};\n/* WEBPACK VAR INJECTION */}.call(exports, __webpack_require__(/*! libs/backbone */ 2), __webpack_require__(/*! underscore */ 1)))//# sourceURL=[module]\n//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiMTUyLmpzIiwic291cmNlcyI6WyJ3ZWJwYWNrOi8vL2dhbGF4eS9zY3JpcHRzL2FwcHMvbG9naW4uanM/YWEyZiJdLCJzb3VyY2VzQ29udGVudCI6WyJpbXBvcnQgalF1ZXJ5IGZyb20gXCJqcXVlcnlcIjtcbnZhciAkID0galF1ZXJ5O1xuaW1wb3J0IEdhbGF4eUFwcCBmcm9tIFwiZ2FsYXh5XCI7XG5pbXBvcnQgX2wgZnJvbSBcInV0aWxzL2xvY2FsaXphdGlvblwiO1xuaW1wb3J0IFBhZ2UgZnJvbSBcImxheW91dC9wYWdlXCI7XG5cbndpbmRvdy5hcHAgPSBmdW5jdGlvbiBhcHAob3B0aW9ucywgYm9vdHN0cmFwcGVkKSB7XG4gICAgd2luZG93LkdhbGF4eSA9IG5ldyBHYWxheHlBcHAuR2FsYXh5QXBwKG9wdGlvbnMsIGJvb3RzdHJhcHBlZCk7XG4gICAgR2FsYXh5LmRlYnVnKFwibG9naW4gYXBwXCIpO1xuICAgIHZhciByZWRpcmVjdCA9IGVuY29kZVVSSShvcHRpb25zLnJlZGlyZWN0KTtcblxuICAgIC8vIFRPRE86IHJlbW92ZSBpZnJhbWUgZm9yIHVzZXIgbG9naW4gKGF0IGxlYXN0KSBhbmQgcmVuZGVyIGxvZ2luIHBhZ2UgZnJvbSBoZXJlXG4gICAgLy8gdGhlbiByZW1vdmUgdGhpcyByZWRpcmVjdFxuICAgIGlmICghb3B0aW9ucy5zaG93X3dlbGNvbWVfd2l0aF9sb2dpbikge1xuICAgICAgICB2YXIgcGFyYW1zID0galF1ZXJ5LnBhcmFtKHsgdXNlX3BhbmVsczogXCJUcnVlXCIsIHJlZGlyZWN0OiByZWRpcmVjdCB9KTtcbiAgICAgICAgd2luZG93LmxvY2F0aW9uLmhyZWYgPSBgJHtHYWxheHkucm9vdH11c2VyL2xvZ2luPyR7cGFyYW1zfWA7XG4gICAgICAgIHJldHVybjtcbiAgICB9XG5cbiAgICB2YXIgTG9naW5QYWdlID0gQmFja2JvbmUuVmlldy5leHRlbmQoe1xuICAgICAgICBpbml0aWFsaXplOiBmdW5jdGlvbihwYWdlKSB7XG4gICAgICAgICAgICB0aGlzLnBhZ2UgPSBwYWdlO1xuICAgICAgICAgICAgdGhpcy5tb2RlbCA9IG5ldyBCYWNrYm9uZS5Nb2RlbCh7IHRpdGxlOiBfbChcIkxvZ2luIHJlcXVpcmVkXCIpIH0pO1xuICAgICAgICAgICAgdGhpcy5zZXRFbGVtZW50KHRoaXMuX3RlbXBsYXRlKCkpO1xuICAgICAgICB9LFxuICAgICAgICByZW5kZXI6IGZ1bmN0aW9uKCkge1xuICAgICAgICAgICAgdGhpcy5wYWdlLiQoXCIjZ2FsYXh5X21haW5cIikucHJvcChcInNyY1wiLCBvcHRpb25zLndlbGNvbWVfdXJsKTtcbiAgICAgICAgfSxcbiAgICAgICAgX3RlbXBsYXRlOiBmdW5jdGlvbigpIHtcbiAgICAgICAgICAgIHZhciBsb2dpbl91cmwgPSBgJHtvcHRpb25zLnJvb3R9dXNlci9sb2dpbj8keyQucGFyYW0oe1xuICAgICAgICAgICAgICAgIHJlZGlyZWN0OiByZWRpcmVjdFxuICAgICAgICAgICAgfSl9YDtcbiAgICAgICAgICAgIHJldHVybiBgPGlmcmFtZSBzcmM9XCIke2xvZ2luX3VybH1cIiBmcmFtZWJvcmRlcj1cIjBcIiBzdHlsZT1cIndpZHRoOiAxMDAlOyBoZWlnaHQ6IDEwMCU7XCIvPmA7XG4gICAgICAgIH1cbiAgICB9KTtcblxuICAgICQoKCkgPT4ge1xuICAgICAgICBHYWxheHkucGFnZSA9IG5ldyBQYWdlLlZpZXcoXG4gICAgICAgICAgICBfLmV4dGVuZChvcHRpb25zLCB7XG4gICAgICAgICAgICAgICAgUmlnaHQ6IExvZ2luUGFnZVxuICAgICAgICAgICAgfSlcbiAgICAgICAgKTtcbiAgICB9KTtcbn07XG5cblxuXG4vLyBXRUJQQUNLIEZPT1RFUiAvL1xuLy8gZ2FsYXh5L3NjcmlwdHMvYXBwcy9sb2dpbi5qcyJdLCJtYXBwaW5ncyI6Ijs7QUFBQTtBQUNBOzs7QUFDQTtBQUNBOzs7QUFBQTtBQUNBOzs7QUFBQTtBQUNBOzs7OztBQUpBO0FBQ0E7QUFDQTtBQUdBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBREE7QUFHQTtBQUNBO0FBZEE7QUFDQTtBQWdCQTtBQUNBO0FBRUE7QUFEQTtBQUlBO0FBQ0E7QSIsInNvdXJjZVJvb3QiOiIifQ==\n//# sourceURL=webpack-internal:///152\n");

/***/ }),

/***/ 43:
/*!***************************************!*\
  !*** ./galaxy/scripts/layout/page.js ***!
  \***************************************/
/*! dynamic exports provided */
/*! all exports used */
/***/ (function(module, exports, __webpack_require__) {

"use strict";
eval("/* WEBPACK VAR INJECTION */(function(Backbone, _, $) {\n\nObject.defineProperty(exports, \"__esModule\", {\n    value: true\n});\n\nvar _masthead = __webpack_require__(/*! layout/masthead */ 68);\n\nvar _masthead2 = _interopRequireDefault(_masthead);\n\nvar _panel = __webpack_require__(/*! layout/panel */ 42);\n\nvar _panel2 = _interopRequireDefault(_panel);\n\nvar _uiModal = __webpack_require__(/*! mvc/ui/ui-modal */ 9);\n\nvar _uiModal2 = _interopRequireDefault(_uiModal);\n\nvar _utils = __webpack_require__(/*! utils/utils */ 5);\n\nvar _utils2 = _interopRequireDefault(_utils);\n\nfunction _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }\n\nvar View = Backbone.View.extend({\n    el: \"body\",\n    className: \"full-content\",\n    _panelids: [\"left\", \"right\"],\n\n    initialize: function initialize(options) {\n        var self = this;\n        this.config = _.defaults(options.config || {}, {\n            message_box_visible: false,\n            message_box_content: \"\",\n            message_box_class: \"info\",\n            show_inactivity_warning: false,\n            inactivity_box_content: \"\"\n        });\n\n        // attach global objects, build mastheads\n        Galaxy.modal = this.modal = new _uiModal2.default.View();\n        Galaxy.display = this.display = function (view) {\n            if (view.title) {\n                _utils2.default.setWindowTitle(view.title);\n                view.allow_title_display = false;\n            } else {\n                _utils2.default.setWindowTitle();\n                view.allow_title_display = true;\n            }\n            self.center.display(view);\n        };\n        Galaxy.router = this.router = options.Router && new options.Router(self, options);\n        this.masthead = new _masthead2.default.View(this.config);\n        this.center = new _panel2.default.CenterPanel();\n\n        // build page template\n        this.$el.attr(\"scroll\", \"no\");\n        this.$el.html(this._template());\n        this.$(\"#masthead\").replaceWith(this.masthead.$el);\n        this.$(\"#center\").append(this.center.$el);\n        this.$el.append(this.masthead.frame.$el);\n        this.$el.append(this.modal.$el);\n        this.$messagebox = this.$(\"#messagebox\");\n        this.$inactivebox = this.$(\"#inactivebox\");\n\n        // build panels\n        this.panels = {};\n        _.each(this._panelids, function (panel_id) {\n            var panel_class_name = panel_id.charAt(0).toUpperCase() + panel_id.slice(1);\n            var panel_class = options[panel_class_name];\n            if (panel_class) {\n                var panel_instance = new panel_class(self, options);\n                self[panel_instance.toString()] = panel_instance;\n                self.panels[panel_id] = new _panel2.default.SidePanel({\n                    id: panel_id,\n                    el: self.$(\"#\" + panel_id),\n                    view: panel_instance\n                });\n            }\n        });\n        this.render();\n\n        // start the router\n        if (this.router) {\n            Backbone.history.start({\n                root: Galaxy.root,\n                pushState: true\n            });\n        }\n    },\n\n    render: function render() {\n        // TODO: Remove this line after select2 update\n        $(\".select2-hidden-accessible\").remove();\n        this.masthead.render();\n        this.renderMessageBox();\n        this.renderInactivityBox();\n        this.renderPanels();\n        this._checkCommunicationServerOnline();\n        return this;\n    },\n\n    /** Render message box */\n    renderMessageBox: function renderMessageBox() {\n        if (this.config.message_box_visible) {\n            var content = this.config.message_box_content || \"\";\n            var level = this.config.message_box_class || \"info\";\n            this.$el.addClass(\"has-message-box\");\n            this.$messagebox.attr(\"class\", \"panel-\" + level + \"-message\").html(content).toggle(!!content).show();\n        } else {\n            this.$el.removeClass(\"has-message-box\");\n            this.$messagebox.hide();\n        }\n        return this;\n    },\n\n    /** Render inactivity warning */\n    renderInactivityBox: function renderInactivityBox() {\n        if (this.config.show_inactivity_warning) {\n            var content = this.config.inactivity_box_content || \"\";\n            var verificationLink = $(\"<a/>\").attr(\"href\", Galaxy.root + \"user/resend_verification\").text(\"Resend verification\");\n            this.$el.addClass(\"has-inactivity-box\");\n            this.$inactivebox.html(content + \" \").append(verificationLink).toggle(!!content).show();\n        } else {\n            this.$el.removeClass(\"has-inactivity-box\");\n            this.$inactivebox.hide();\n        }\n        return this;\n    },\n\n    /** Render panels */\n    renderPanels: function renderPanels() {\n        var self = this;\n        _.each(this._panelids, function (panel_id) {\n            var panel = self.panels[panel_id];\n            if (panel) {\n                panel.render();\n            } else {\n                self.$(\"#center\").css(panel_id, 0);\n                self.$(\"#\" + panel_id).hide();\n            }\n        });\n        return this;\n    },\n\n    /** body template */\n    _template: function _template() {\n        return ['<div id=\"everything\">', '<div id=\"background\"/>', '<div id=\"masthead\"/>', '<div id=\"messagebox\"/>', '<div id=\"inactivebox\" class=\"panel-warning-message\" />', '<div id=\"left\" />', '<div id=\"center\" />', '<div id=\"right\" />', \"</div>\", '<div id=\"dd-helper\" />'].join(\"\");\n    },\n\n    toString: function toString() {\n        return \"PageLayoutView\";\n    },\n\n    /** Check if the communication server is online and show the icon otherwise hide the icon */\n    _checkCommunicationServerOnline: function _checkCommunicationServerOnline() {\n        var host = window.Galaxy.config.communication_server_host;\n        var port = window.Galaxy.config.communication_server_port;\n        var preferences = window.Galaxy.user.attributes.preferences;\n        var $chat_icon_element = $(\"#show-chat-online\");\n        /** Check if the user has deactivated the communication in it's personal settings */\n        if (preferences && [\"1\", \"true\"].indexOf(preferences.communication_server) != -1) {\n            // See if the configured communication server is available\n            $.ajax({\n                url: host + \":\" + port\n            }).success(function (data) {\n                // enable communication only when a user is logged in\n                if (window.Galaxy.user.id !== null) {\n                    if ($chat_icon_element.css(\"visibility\") === \"hidden\") {\n                        $chat_icon_element.css(\"visibility\", \"visible\");\n                    }\n                }\n            }).error(function (data) {\n                // hide the communication icon if the communication server is not available\n                $chat_icon_element.css(\"visibility\", \"hidden\");\n            });\n        } else {\n            $chat_icon_element.css(\"visibility\", \"hidden\");\n        }\n    }\n});\n\nexports.default = { View: View };\n/* WEBPACK VAR INJECTION */}.call(exports, __webpack_require__(/*! libs/backbone */ 2), __webpack_require__(/*! underscore */ 1), __webpack_require__(/*! jquery */ 0)))//# sourceURL=[module]\n//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiNDMuanMiLCJzb3VyY2VzIjpbIndlYnBhY2s6Ly8vZ2FsYXh5L3NjcmlwdHMvbGF5b3V0L3BhZ2UuanM/MDU4YyJdLCJzb3VyY2VzQ29udGVudCI6WyJpbXBvcnQgTWFzdGhlYWQgZnJvbSBcImxheW91dC9tYXN0aGVhZFwiO1xuaW1wb3J0IFBhbmVsIGZyb20gXCJsYXlvdXQvcGFuZWxcIjtcbmltcG9ydCBNb2RhbCBmcm9tIFwibXZjL3VpL3VpLW1vZGFsXCI7XG5pbXBvcnQgVXRpbHMgZnJvbSBcInV0aWxzL3V0aWxzXCI7XG5cbnZhciBWaWV3ID0gQmFja2JvbmUuVmlldy5leHRlbmQoe1xuICAgIGVsOiBcImJvZHlcIixcbiAgICBjbGFzc05hbWU6IFwiZnVsbC1jb250ZW50XCIsXG4gICAgX3BhbmVsaWRzOiBbXCJsZWZ0XCIsIFwicmlnaHRcIl0sXG5cbiAgICBpbml0aWFsaXplOiBmdW5jdGlvbihvcHRpb25zKSB7XG4gICAgICAgIHZhciBzZWxmID0gdGhpcztcbiAgICAgICAgdGhpcy5jb25maWcgPSBfLmRlZmF1bHRzKG9wdGlvbnMuY29uZmlnIHx8IHt9LCB7XG4gICAgICAgICAgICBtZXNzYWdlX2JveF92aXNpYmxlOiBmYWxzZSxcbiAgICAgICAgICAgIG1lc3NhZ2VfYm94X2NvbnRlbnQ6IFwiXCIsXG4gICAgICAgICAgICBtZXNzYWdlX2JveF9jbGFzczogXCJpbmZvXCIsXG4gICAgICAgICAgICBzaG93X2luYWN0aXZpdHlfd2FybmluZzogZmFsc2UsXG4gICAgICAgICAgICBpbmFjdGl2aXR5X2JveF9jb250ZW50OiBcIlwiXG4gICAgICAgIH0pO1xuXG4gICAgICAgIC8vIGF0dGFjaCBnbG9iYWwgb2JqZWN0cywgYnVpbGQgbWFzdGhlYWRzXG4gICAgICAgIEdhbGF4eS5tb2RhbCA9IHRoaXMubW9kYWwgPSBuZXcgTW9kYWwuVmlldygpO1xuICAgICAgICBHYWxheHkuZGlzcGxheSA9IHRoaXMuZGlzcGxheSA9IHZpZXcgPT4ge1xuICAgICAgICAgICAgaWYgKHZpZXcudGl0bGUpIHtcbiAgICAgICAgICAgICAgICBVdGlscy5zZXRXaW5kb3dUaXRsZSh2aWV3LnRpdGxlKTtcbiAgICAgICAgICAgICAgICB2aWV3LmFsbG93X3RpdGxlX2Rpc3BsYXkgPSBmYWxzZTtcbiAgICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICAgICAgVXRpbHMuc2V0V2luZG93VGl0bGUoKTtcbiAgICAgICAgICAgICAgICB2aWV3LmFsbG93X3RpdGxlX2Rpc3BsYXkgPSB0cnVlO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgc2VsZi5jZW50ZXIuZGlzcGxheSh2aWV3KTtcbiAgICAgICAgfTtcbiAgICAgICAgR2FsYXh5LnJvdXRlciA9IHRoaXMucm91dGVyID0gb3B0aW9ucy5Sb3V0ZXIgJiYgbmV3IG9wdGlvbnMuUm91dGVyKHNlbGYsIG9wdGlvbnMpO1xuICAgICAgICB0aGlzLm1hc3RoZWFkID0gbmV3IE1hc3RoZWFkLlZpZXcodGhpcy5jb25maWcpO1xuICAgICAgICB0aGlzLmNlbnRlciA9IG5ldyBQYW5lbC5DZW50ZXJQYW5lbCgpO1xuXG4gICAgICAgIC8vIGJ1aWxkIHBhZ2UgdGVtcGxhdGVcbiAgICAgICAgdGhpcy4kZWwuYXR0cihcInNjcm9sbFwiLCBcIm5vXCIpO1xuICAgICAgICB0aGlzLiRlbC5odG1sKHRoaXMuX3RlbXBsYXRlKCkpO1xuICAgICAgICB0aGlzLiQoXCIjbWFzdGhlYWRcIikucmVwbGFjZVdpdGgodGhpcy5tYXN0aGVhZC4kZWwpO1xuICAgICAgICB0aGlzLiQoXCIjY2VudGVyXCIpLmFwcGVuZCh0aGlzLmNlbnRlci4kZWwpO1xuICAgICAgICB0aGlzLiRlbC5hcHBlbmQodGhpcy5tYXN0aGVhZC5mcmFtZS4kZWwpO1xuICAgICAgICB0aGlzLiRlbC5hcHBlbmQodGhpcy5tb2RhbC4kZWwpO1xuICAgICAgICB0aGlzLiRtZXNzYWdlYm94ID0gdGhpcy4kKFwiI21lc3NhZ2Vib3hcIik7XG4gICAgICAgIHRoaXMuJGluYWN0aXZlYm94ID0gdGhpcy4kKFwiI2luYWN0aXZlYm94XCIpO1xuXG4gICAgICAgIC8vIGJ1aWxkIHBhbmVsc1xuICAgICAgICB0aGlzLnBhbmVscyA9IHt9O1xuICAgICAgICBfLmVhY2godGhpcy5fcGFuZWxpZHMsIHBhbmVsX2lkID0+IHtcbiAgICAgICAgICAgIHZhciBwYW5lbF9jbGFzc19uYW1lID0gcGFuZWxfaWQuY2hhckF0KDApLnRvVXBwZXJDYXNlKCkgKyBwYW5lbF9pZC5zbGljZSgxKTtcbiAgICAgICAgICAgIHZhciBwYW5lbF9jbGFzcyA9IG9wdGlvbnNbcGFuZWxfY2xhc3NfbmFtZV07XG4gICAgICAgICAgICBpZiAocGFuZWxfY2xhc3MpIHtcbiAgICAgICAgICAgICAgICB2YXIgcGFuZWxfaW5zdGFuY2UgPSBuZXcgcGFuZWxfY2xhc3Moc2VsZiwgb3B0aW9ucyk7XG4gICAgICAgICAgICAgICAgc2VsZltwYW5lbF9pbnN0YW5jZS50b1N0cmluZygpXSA9IHBhbmVsX2luc3RhbmNlO1xuICAgICAgICAgICAgICAgIHNlbGYucGFuZWxzW3BhbmVsX2lkXSA9IG5ldyBQYW5lbC5TaWRlUGFuZWwoe1xuICAgICAgICAgICAgICAgICAgICBpZDogcGFuZWxfaWQsXG4gICAgICAgICAgICAgICAgICAgIGVsOiBzZWxmLiQoYCMke3BhbmVsX2lkfWApLFxuICAgICAgICAgICAgICAgICAgICB2aWV3OiBwYW5lbF9pbnN0YW5jZVxuICAgICAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgfVxuICAgICAgICB9KTtcbiAgICAgICAgdGhpcy5yZW5kZXIoKTtcblxuICAgICAgICAvLyBzdGFydCB0aGUgcm91dGVyXG4gICAgICAgIGlmICh0aGlzLnJvdXRlcikge1xuICAgICAgICAgICAgQmFja2JvbmUuaGlzdG9yeS5zdGFydCh7XG4gICAgICAgICAgICAgICAgcm9vdDogR2FsYXh5LnJvb3QsXG4gICAgICAgICAgICAgICAgcHVzaFN0YXRlOiB0cnVlXG4gICAgICAgICAgICB9KTtcbiAgICAgICAgfVxuICAgIH0sXG5cbiAgICByZW5kZXI6IGZ1bmN0aW9uKCkge1xuICAgICAgICAvLyBUT0RPOiBSZW1vdmUgdGhpcyBsaW5lIGFmdGVyIHNlbGVjdDIgdXBkYXRlXG4gICAgICAgICQoXCIuc2VsZWN0Mi1oaWRkZW4tYWNjZXNzaWJsZVwiKS5yZW1vdmUoKTtcbiAgICAgICAgdGhpcy5tYXN0aGVhZC5yZW5kZXIoKTtcbiAgICAgICAgdGhpcy5yZW5kZXJNZXNzYWdlQm94KCk7XG4gICAgICAgIHRoaXMucmVuZGVySW5hY3Rpdml0eUJveCgpO1xuICAgICAgICB0aGlzLnJlbmRlclBhbmVscygpO1xuICAgICAgICB0aGlzLl9jaGVja0NvbW11bmljYXRpb25TZXJ2ZXJPbmxpbmUoKTtcbiAgICAgICAgcmV0dXJuIHRoaXM7XG4gICAgfSxcblxuICAgIC8qKiBSZW5kZXIgbWVzc2FnZSBib3ggKi9cbiAgICByZW5kZXJNZXNzYWdlQm94OiBmdW5jdGlvbigpIHtcbiAgICAgICAgaWYgKHRoaXMuY29uZmlnLm1lc3NhZ2VfYm94X3Zpc2libGUpIHtcbiAgICAgICAgICAgIHZhciBjb250ZW50ID0gdGhpcy5jb25maWcubWVzc2FnZV9ib3hfY29udGVudCB8fCBcIlwiO1xuICAgICAgICAgICAgdmFyIGxldmVsID0gdGhpcy5jb25maWcubWVzc2FnZV9ib3hfY2xhc3MgfHwgXCJpbmZvXCI7XG4gICAgICAgICAgICB0aGlzLiRlbC5hZGRDbGFzcyhcImhhcy1tZXNzYWdlLWJveFwiKTtcbiAgICAgICAgICAgIHRoaXMuJG1lc3NhZ2Vib3hcbiAgICAgICAgICAgICAgICAuYXR0cihcImNsYXNzXCIsIGBwYW5lbC0ke2xldmVsfS1tZXNzYWdlYClcbiAgICAgICAgICAgICAgICAuaHRtbChjb250ZW50KVxuICAgICAgICAgICAgICAgIC50b2dnbGUoISFjb250ZW50KVxuICAgICAgICAgICAgICAgIC5zaG93KCk7XG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICB0aGlzLiRlbC5yZW1vdmVDbGFzcyhcImhhcy1tZXNzYWdlLWJveFwiKTtcbiAgICAgICAgICAgIHRoaXMuJG1lc3NhZ2Vib3guaGlkZSgpO1xuICAgICAgICB9XG4gICAgICAgIHJldHVybiB0aGlzO1xuICAgIH0sXG5cbiAgICAvKiogUmVuZGVyIGluYWN0aXZpdHkgd2FybmluZyAqL1xuICAgIHJlbmRlckluYWN0aXZpdHlCb3g6IGZ1bmN0aW9uKCkge1xuICAgICAgICBpZiAodGhpcy5jb25maWcuc2hvd19pbmFjdGl2aXR5X3dhcm5pbmcpIHtcbiAgICAgICAgICAgIHZhciBjb250ZW50ID0gdGhpcy5jb25maWcuaW5hY3Rpdml0eV9ib3hfY29udGVudCB8fCBcIlwiO1xuICAgICAgICAgICAgdmFyIHZlcmlmaWNhdGlvbkxpbmsgPSAkKFwiPGEvPlwiKVxuICAgICAgICAgICAgICAgIC5hdHRyKFwiaHJlZlwiLCBgJHtHYWxheHkucm9vdH11c2VyL3Jlc2VuZF92ZXJpZmljYXRpb25gKVxuICAgICAgICAgICAgICAgIC50ZXh0KFwiUmVzZW5kIHZlcmlmaWNhdGlvblwiKTtcbiAgICAgICAgICAgIHRoaXMuJGVsLmFkZENsYXNzKFwiaGFzLWluYWN0aXZpdHktYm94XCIpO1xuICAgICAgICAgICAgdGhpcy4kaW5hY3RpdmVib3hcbiAgICAgICAgICAgICAgICAuaHRtbChgJHtjb250ZW50fSBgKVxuICAgICAgICAgICAgICAgIC5hcHBlbmQodmVyaWZpY2F0aW9uTGluaylcbiAgICAgICAgICAgICAgICAudG9nZ2xlKCEhY29udGVudClcbiAgICAgICAgICAgICAgICAuc2hvdygpO1xuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgdGhpcy4kZWwucmVtb3ZlQ2xhc3MoXCJoYXMtaW5hY3Rpdml0eS1ib3hcIik7XG4gICAgICAgICAgICB0aGlzLiRpbmFjdGl2ZWJveC5oaWRlKCk7XG4gICAgICAgIH1cbiAgICAgICAgcmV0dXJuIHRoaXM7XG4gICAgfSxcblxuICAgIC8qKiBSZW5kZXIgcGFuZWxzICovXG4gICAgcmVuZGVyUGFuZWxzOiBmdW5jdGlvbigpIHtcbiAgICAgICAgdmFyIHNlbGYgPSB0aGlzO1xuICAgICAgICBfLmVhY2godGhpcy5fcGFuZWxpZHMsIHBhbmVsX2lkID0+IHtcbiAgICAgICAgICAgIHZhciBwYW5lbCA9IHNlbGYucGFuZWxzW3BhbmVsX2lkXTtcbiAgICAgICAgICAgIGlmIChwYW5lbCkge1xuICAgICAgICAgICAgICAgIHBhbmVsLnJlbmRlcigpO1xuICAgICAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgICAgICBzZWxmLiQoXCIjY2VudGVyXCIpLmNzcyhwYW5lbF9pZCwgMCk7XG4gICAgICAgICAgICAgICAgc2VsZi4kKGAjJHtwYW5lbF9pZH1gKS5oaWRlKCk7XG4gICAgICAgICAgICB9XG4gICAgICAgIH0pO1xuICAgICAgICByZXR1cm4gdGhpcztcbiAgICB9LFxuXG4gICAgLyoqIGJvZHkgdGVtcGxhdGUgKi9cbiAgICBfdGVtcGxhdGU6IGZ1bmN0aW9uKCkge1xuICAgICAgICByZXR1cm4gW1xuICAgICAgICAgICAgJzxkaXYgaWQ9XCJldmVyeXRoaW5nXCI+JyxcbiAgICAgICAgICAgICc8ZGl2IGlkPVwiYmFja2dyb3VuZFwiLz4nLFxuICAgICAgICAgICAgJzxkaXYgaWQ9XCJtYXN0aGVhZFwiLz4nLFxuICAgICAgICAgICAgJzxkaXYgaWQ9XCJtZXNzYWdlYm94XCIvPicsXG4gICAgICAgICAgICAnPGRpdiBpZD1cImluYWN0aXZlYm94XCIgY2xhc3M9XCJwYW5lbC13YXJuaW5nLW1lc3NhZ2VcIiAvPicsXG4gICAgICAgICAgICAnPGRpdiBpZD1cImxlZnRcIiAvPicsXG4gICAgICAgICAgICAnPGRpdiBpZD1cImNlbnRlclwiIC8+JyxcbiAgICAgICAgICAgICc8ZGl2IGlkPVwicmlnaHRcIiAvPicsXG4gICAgICAgICAgICBcIjwvZGl2PlwiLFxuICAgICAgICAgICAgJzxkaXYgaWQ9XCJkZC1oZWxwZXJcIiAvPidcbiAgICAgICAgXS5qb2luKFwiXCIpO1xuICAgIH0sXG5cbiAgICB0b1N0cmluZzogZnVuY3Rpb24oKSB7XG4gICAgICAgIHJldHVybiBcIlBhZ2VMYXlvdXRWaWV3XCI7XG4gICAgfSxcblxuICAgIC8qKiBDaGVjayBpZiB0aGUgY29tbXVuaWNhdGlvbiBzZXJ2ZXIgaXMgb25saW5lIGFuZCBzaG93IHRoZSBpY29uIG90aGVyd2lzZSBoaWRlIHRoZSBpY29uICovXG4gICAgX2NoZWNrQ29tbXVuaWNhdGlvblNlcnZlck9ubGluZTogZnVuY3Rpb24oKSB7XG4gICAgICAgIHZhciBob3N0ID0gd2luZG93LkdhbGF4eS5jb25maWcuY29tbXVuaWNhdGlvbl9zZXJ2ZXJfaG9zdDtcbiAgICAgICAgdmFyIHBvcnQgPSB3aW5kb3cuR2FsYXh5LmNvbmZpZy5jb21tdW5pY2F0aW9uX3NlcnZlcl9wb3J0O1xuICAgICAgICB2YXIgcHJlZmVyZW5jZXMgPSB3aW5kb3cuR2FsYXh5LnVzZXIuYXR0cmlidXRlcy5wcmVmZXJlbmNlcztcbiAgICAgICAgdmFyICRjaGF0X2ljb25fZWxlbWVudCA9ICQoXCIjc2hvdy1jaGF0LW9ubGluZVwiKTtcbiAgICAgICAgLyoqIENoZWNrIGlmIHRoZSB1c2VyIGhhcyBkZWFjdGl2YXRlZCB0aGUgY29tbXVuaWNhdGlvbiBpbiBpdCdzIHBlcnNvbmFsIHNldHRpbmdzICovXG4gICAgICAgIGlmIChwcmVmZXJlbmNlcyAmJiBbXCIxXCIsIFwidHJ1ZVwiXS5pbmRleE9mKHByZWZlcmVuY2VzLmNvbW11bmljYXRpb25fc2VydmVyKSAhPSAtMSkge1xuICAgICAgICAgICAgLy8gU2VlIGlmIHRoZSBjb25maWd1cmVkIGNvbW11bmljYXRpb24gc2VydmVyIGlzIGF2YWlsYWJsZVxuICAgICAgICAgICAgJC5hamF4KHtcbiAgICAgICAgICAgICAgICB1cmw6IGAke2hvc3R9OiR7cG9ydH1gXG4gICAgICAgICAgICB9KVxuICAgICAgICAgICAgICAgIC5zdWNjZXNzKGRhdGEgPT4ge1xuICAgICAgICAgICAgICAgICAgICAvLyBlbmFibGUgY29tbXVuaWNhdGlvbiBvbmx5IHdoZW4gYSB1c2VyIGlzIGxvZ2dlZCBpblxuICAgICAgICAgICAgICAgICAgICBpZiAod2luZG93LkdhbGF4eS51c2VyLmlkICE9PSBudWxsKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICBpZiAoJGNoYXRfaWNvbl9lbGVtZW50LmNzcyhcInZpc2liaWxpdHlcIikgPT09IFwiaGlkZGVuXCIpIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAkY2hhdF9pY29uX2VsZW1lbnQuY3NzKFwidmlzaWJpbGl0eVwiLCBcInZpc2libGVcIik7XG4gICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9KVxuICAgICAgICAgICAgICAgIC5lcnJvcihkYXRhID0+IHtcbiAgICAgICAgICAgICAgICAgICAgLy8gaGlkZSB0aGUgY29tbXVuaWNhdGlvbiBpY29uIGlmIHRoZSBjb21tdW5pY2F0aW9uIHNlcnZlciBpcyBub3QgYXZhaWxhYmxlXG4gICAgICAgICAgICAgICAgICAgICRjaGF0X2ljb25fZWxlbWVudC5jc3MoXCJ2aXNpYmlsaXR5XCIsIFwiaGlkZGVuXCIpO1xuICAgICAgICAgICAgICAgIH0pO1xuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgJGNoYXRfaWNvbl9lbGVtZW50LmNzcyhcInZpc2liaWxpdHlcIiwgXCJoaWRkZW5cIik7XG4gICAgICAgIH1cbiAgICB9XG59KTtcblxuZXhwb3J0IGRlZmF1bHQgeyBWaWV3OiBWaWV3IH07XG5cblxuXG4vLyBXRUJQQUNLIEZPT1RFUiAvL1xuLy8gZ2FsYXh5L3NjcmlwdHMvbGF5b3V0L3BhZ2UuanMiXSwibWFwcGluZ3MiOiI7Ozs7OztBQUFBO0FBQ0E7OztBQUFBO0FBQ0E7OztBQUFBO0FBQ0E7OztBQUFBO0FBQ0E7Ozs7O0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFMQTtBQUNBO0FBT0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUhBO0FBS0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBRkE7QUFJQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFLQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFHQTtBQUNBO0FBS0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFZQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBREE7QUFJQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUVBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBbExBO0FBQ0E7QUFvTEE7QSIsInNvdXJjZVJvb3QiOiIifQ==\n//# sourceURL=webpack-internal:///43\n");

/***/ })

},[152]);