"use strict";define(["utils/utils","mvc/ui/ui-portlet","mvc/ui/ui-misc"],function(t,i,e){return{View:Backbone.View.extend({initialize:function(t){var s=this;this.options=t,this.name=t.name||"element",this.multiple=t.multiple||!1,this.message=new e.Message,this.portlet=new i.View({cls:"ui-portlet-section"}),this.select=new e.Select.View({optional:t.optional}),this.button=new e.ButtonIcon({icon:"fa fa-sign-in",tooltip:"Insert new "+this.name,onclick:function(){s.add({id:s.select.value(),name:s.select.text()})}}),this.setElement(this._template(t)),this.$(".ui-list-message").append(this.message.$el),this.$(".ui-list-portlet").append(this.portlet.$el),this.$(".ui-list-button").append(this.button.$el),this.$(".ui-list-select").append(this.select.$el)},value:function(t){if(void 0!==t){if(this.portlet.empty(),$.isArray(t))for(var i in t){var e=t[i],s=null,n=null;"string"!=$.type(e)?(s=e.id,n=e.name):s=n=e,null!=s&&this.add({id:s,name:n})}this._refresh()}var l=[];return this.$(".ui-list-id").each(function(){l.push({id:$(this).prop("id"),name:$(this).find(".ui-list-name").html()})}),0==l.length?null:l},add:function(i){var e=this;if(0===this.$('[id="'+i.id+'"]').length)if(t.isEmpty(i.id))this.message.update({message:"Please select a valid "+this.name+".",status:"danger"});else{var s=$(this._templateRow({id:i.id,name:i.name}));s.on("click",function(){s.remove(),e._refresh()}),s.on("mouseover",function(){s.addClass("portlet-highlight")}),s.on("mouseout",function(){s.removeClass("portlet-highlight")}),this.portlet.append(s),this._refresh()}else this.message.update({message:"This "+this.name+" is already in the list."})},update:function(t){this.select.update(t)},_refresh:function(){this.$(".ui-list-id").length>0?(!this.multiple&&this.button.disable(),this.$(".ui-list-portlet").show()):(this.button.enable(),this.$(".ui-list-portlet").hide()),this.options.onchange&&this.options.onchange()},_template:function(t){return'<div class="ui-list"><div class="ui-margin-top"><span class="ui-list-button"/><span class="ui-list-select"/></div><div class="ui-list-message"/><div class="ui-list-portlet"/></div>'},_templateRow:function(t){return'<div id="'+t.id+'" class="ui-list-id"><span class="ui-list-delete fa fa-trash"/><span class="ui-list-name">'+t.name+"</span></div>"}})}});
//# sourceMappingURL=../../../maps/mvc/ui/ui-list.js.map
