import asyncio
import os
from typing import Any, Dict, List, Optional, Tuple

import astrbot.api.star as star
import astrbot.api.event.filter as filter
from astrbot.api.event import AstrMessageEvent, MessageChain
from astrbot.api import sp, logger
from astrbot.core import file_token_service
from astrbot.core.star.star_handler import star_handlers_registry, StarHandlerMetadata
from astrbot.core.star.star import star_map
from astrbot.core.star.filter.command import CommandFilter
from astrbot.core.star.filter.command_group import CommandGroupFilter
from astrbot.core.star.filter.permission import PermissionTypeFilter, PermissionType
from astrbot.core.utils.command_parser import CommandParserMixin
from quart import jsonify, request, send_file

PLUGIN_NAME = "astrbot_plugin_permission_manager"

class PermissionManagerCommands(CommandParserMixin):
    """批量权限管理逻辑类"""
    def __init__(self, context: star.Context):
        self.context = context

    def _get_plugin_metadata(self, plugin_name: str) -> Dict[str, Any]:
        if plugin_name == "builtin_commands":
            return {
                "display_name": "系统内置指令",
                "desc": "AstrBot 核心自带的系统内置管理和功能指令",
                "author": "AstrBot",
                "version": "内置",
                "has_logo": False,
                "logo_path": None
            }
        for plugin in star_map.values():
            if plugin.name == plugin_name:
                return {
                    "display_name": plugin.display_name or plugin.name,
                    "desc": plugin.desc or plugin.short_desc or "暂无简介",
                    "author": plugin.author or "未知",
                    "version": plugin.version or "1.0.0",
                    "has_logo": bool(plugin.logo_path and os.path.exists(plugin.logo_path)),
                    "logo_path": plugin.logo_path if plugin.logo_path and os.path.exists(plugin.logo_path) else None
                }
        return {
            "display_name": plugin_name,
            "desc": "暂无简介",
            "author": "未知",
            "version": "1.0.0",
            "has_logo": False,
            "logo_path": None
        }

    def _get_all_commands_by_plugin(self) -> Dict[str, List[tuple]]:
        plugin_commands = {}
        for handler in star_handlers_registry:
            assert isinstance(handler, StarHandlerMetadata)
            
            # 判断内置命令或外部插件
            plugin_name = None
            if handler.handler_module_path in star_map:
                plugin = star_map[handler.handler_module_path]
                if not plugin.activated: continue
                plugin_name = plugin.name
            elif "builtin" in handler.handler_module_path:
                plugin_name = "builtin_commands"
            else:
                parts = handler.handler_module_path.split('.')
                if len(parts) >= 3 and parts[0] == "data" and parts[1] == "plugins":
                    plugin_name = parts[2]
                else:
                    plugin_name = "builtin_commands"
                    
            if plugin_name not in plugin_commands: plugin_commands[plugin_name] = []
            
            for event_filter in handler.event_filters:
                if isinstance(event_filter, CommandFilter):
                    plugin_commands[plugin_name].append((handler, event_filter.command_name, "command", False))
                    break
                elif isinstance(event_filter, CommandGroupFilter):
                    plugin_commands[plugin_name].append((handler, event_filter.group_name, "command_group", True))
                    break
        return plugin_commands

    async def get_all_plugins_api(self):
        plugin_commands = self._get_all_commands_by_plugin()
        plugins = []
        for name, cmds in plugin_commands.items():
            meta = self._get_plugin_metadata(name)
            plugins.append({
                "name": name,
                "display_name": meta["display_name"],
                "desc": meta["desc"],
                "author": meta["author"],
                "version": meta["version"],
                "has_logo": meta["has_logo"],
                "logo": f"/api/file/{await file_token_service.register_file(meta['logo_path'], timeout=300)}" if meta["logo_path"] else None,
                "command_count": len([c for c in cmds if c[2] == "command"]),
                "group_count": len([c for c in cmds if c[3]]),
                "total_commands": len(cmds)
            })
        plugins.sort(key=lambda x: x["display_name"].lower())
        return plugins

    async def get_plugin_commands_api(self, plugin_name: str):
        plugin_commands = self._get_all_commands_by_plugin()
        if plugin_name not in plugin_commands: return None
        cmds = plugin_commands[plugin_name]
        alter_cmd_cfg = await sp.global_get("alter_cmd", {})
        plugin_cfg = alter_cmd_cfg.get(plugin_name, {})
        
        command_list = []
        group_list = []
        for handler, cmd_name, cmd_type, is_group in cmds:
            cmd_cfg = plugin_cfg.get(handler.handler_name, {})
            current_perm = cmd_cfg.get("permission", "未设置")
            if current_perm == "未设置":
                current_perm = "everyone"
                for f in handler.event_filters:
                    if isinstance(f, PermissionTypeFilter):
                        current_perm = "admin" if f.permission_type == PermissionType.ADMIN else "member"
                        break
            
            aliases = cmd_cfg.get("aliases", [])
            if not aliases:
                for f in handler.event_filters:
                    if isinstance(f, (CommandFilter, CommandGroupFilter)) and f.alias:
                        aliases = list(f.alias); break

            info = {
                "name": cmd_cfg.get("name", cmd_name),
                "original_name": cmd_name,
                "handler": handler.handler_name,
                "permission": current_perm,
                "aliases": aliases,
                "desc": handler.desc or ""
            }
            if is_group: group_list.append(info)
            else: command_list.append(info)
            
        command_list.sort(key=lambda x: x["name"].lower())
        group_list.sort(key=lambda x: x["name"].lower())
        return {"commands": command_list, "groups": group_list}

    async def get_all_commands_api(self):
        plugin_commands = self._get_all_commands_by_plugin()
        alter_cmd_cfg = await sp.global_get("alter_cmd", {})
        
        all_cmds = []
        for plugin_name, cmds in plugin_commands.items():
            plugin_cfg = alter_cmd_cfg.get(plugin_name, {})
            meta = self._get_plugin_metadata(plugin_name)
            
            for handler, cmd_name, cmd_type, is_group in cmds:
                cmd_cfg = plugin_cfg.get(handler.handler_name, {})
                current_perm = cmd_cfg.get("permission", "未设置")
                if current_perm == "未设置":
                    current_perm = "everyone"
                    for f in handler.event_filters:
                        if isinstance(f, PermissionTypeFilter):
                            current_perm = "admin" if f.permission_type == PermissionType.ADMIN else "member"
                            break
                
                aliases = cmd_cfg.get("aliases", [])
                if not aliases:
                    for f in handler.event_filters:
                        if isinstance(f, (CommandFilter, CommandGroupFilter)) and f.alias:
                            aliases = list(f.alias); break

                all_cmds.append({
                    "plugin_name": plugin_name,
                    "plugin_display_name": meta["display_name"],
                    "name": cmd_cfg.get("name", cmd_name),
                    "original_name": cmd_name,
                    "handler": handler.handler_name,
                    "permission": current_perm,
                    "aliases": aliases,
                    "desc": handler.desc or "",
                    "is_group": is_group
                })
        all_cmds.sort(key=lambda x: x["name"].lower())
        return all_cmds

    def _get_plugin_name_for_handler(self, handler: StarHandlerMetadata) -> str:
        if handler.handler_module_path in star_map:
            return star_map[handler.handler_module_path].name
        if "builtin" in handler.handler_module_path:
            return "builtin_commands"
        parts = handler.handler_module_path.split('.')
        if len(parts) >= 3 and parts[0] == "data" and parts[1] == "plugins":
            return parts[2]
        return "builtin_commands"

    def _find_handler(self, plugin_name: str, handler_name: str) -> Optional[StarHandlerMetadata]:
        for handler in star_handlers_registry:
            if handler.handler_name == handler_name and self._get_plugin_name_for_handler(handler) == plugin_name:
                return handler
        return None

    def _refresh_group_children(self, group_filter: CommandGroupFilter) -> None:
        group_filter._cmpl_cmd_names = None
        parent_names = group_filter.get_complete_command_names()
        for sub_filter in group_filter.sub_command_filters:
            if isinstance(sub_filter, CommandFilter):
                sub_filter.parent_command_names = parent_names
                sub_filter._cmpl_cmd_names = None
            elif isinstance(sub_filter, CommandGroupFilter):
                sub_filter.parent_group = group_filter
                self._refresh_group_children(sub_filter)

    def _apply_command_identity(self, handler: StarHandlerMetadata, name: Optional[str] = None, aliases: Optional[List[str]] = None) -> bool:
        for event_filter in handler.event_filters:
            if isinstance(event_filter, CommandFilter):
                if name is not None:
                    event_filter.command_name = name
                if aliases is not None:
                    event_filter.alias = set(aliases)
                event_filter._cmpl_cmd_names = None
                return True
            if isinstance(event_filter, CommandGroupFilter):
                if name is not None:
                    event_filter.group_name = name
                if aliases is not None:
                    event_filter.alias = set(aliases)
                self._refresh_group_children(event_filter)
                return True
        return False

    async def set_command_permission(self, plugin_name, handler_name, permission):
        alter_cmd_cfg = await sp.global_get("alter_cmd", {})
        plugin_cfg = alter_cmd_cfg.setdefault(plugin_name, {})
        cmd_cfg = plugin_cfg.setdefault(handler_name, {})
        cmd_cfg["permission"] = permission
        await sp.global_put("alter_cmd", alter_cmd_cfg)
        
        for handler in star_handlers_registry:
            if handler.handler_name == handler_name:
                if permission == "everyone":
                    # 从 handler.event_filters 中移除 PermissionTypeFilter
                    handler.event_filters = [f for f in handler.event_filters if not isinstance(f, PermissionTypeFilter)]
                else:
                    target = PermissionType.ADMIN if permission == "admin" else PermissionType.MEMBER
                    found = False
                    for f in handler.event_filters:
                        if isinstance(f, PermissionTypeFilter):
                            f.permission_type = target; found = True; break
                    if not found:
                        handler.event_filters.append(PermissionTypeFilter(target))
                break
        return True

    async def apply_all_permissions(self):
        alter_cmd_cfg = await sp.global_get("alter_cmd", {})
        if not alter_cmd_cfg: return
        
        logger.info("[PermissionManager] 正在自动应用已保存的指令权限配置...")
        applied_count = 0
        
        for handler in star_handlers_registry:
            assert isinstance(handler, StarHandlerMetadata)
            
            # 判断 handler 属于哪个插件
            plugin_name = None
            if handler.handler_module_path in star_map:
                plugin_name = star_map[handler.handler_module_path].name
            elif "builtin" in handler.handler_module_path:
                plugin_name = "builtin_commands"
            else:
                parts = handler.handler_module_path.split('.')
                if len(parts) >= 3 and parts[0] == "data" and parts[1] == "plugins":
                    plugin_name = parts[2]
                else:
                    plugin_name = "builtin_commands"
            
            if not plugin_name:
                continue
                
            plugin_cfg = alter_cmd_cfg.get(plugin_name, {})
            cmd_cfg = plugin_cfg.get(handler.handler_name, {})
            permission = cmd_cfg.get("permission")
            name = cmd_cfg.get("name")
            aliases = cmd_cfg.get("aliases") if "aliases" in cmd_cfg else None

            if name is not None or aliases is not None:
                if self._apply_command_identity(handler, name=name, aliases=aliases):
                    applied_count += 1

            if permission in ["admin", "member"]:
                target = PermissionType.ADMIN if permission == "admin" else PermissionType.MEMBER
                found = False
                for f in handler.event_filters:
                    if isinstance(f, PermissionTypeFilter):
                        f.permission_type = target; found = True; break
                if not found: 
                    handler.event_filters.append(PermissionTypeFilter(target))
                applied_count += 1
            elif permission == "everyone":
                handler.event_filters = [f for f in handler.event_filters if not isinstance(f, PermissionTypeFilter)]
                applied_count += 1
                
        logger.info(f"[PermissionManager] 成功自动应用了 {applied_count} 个指令的权限配置！")


    async def get_all_tools_api(self):
        llm_tools = self.context.provider_manager.llm_tools
        
        # 内置工具
        builtin_tools = llm_tools.iter_builtin_tools()
        # 其他插件/MCP工具
        other_tools = llm_tools.func_list
        
        all_tools = []
        
        # 1. 内置工具
        for t in builtin_tools:
            all_tools.append({
                "name": t.name,
                "desc": t.description or "无描述",
                "active": getattr(t, "active", True),
                "type": "builtin"
            })
            
        # 2. 其他工具
        for t in other_tools:
            t_type = "plugin"
            if hasattr(t, "mcp_server_name") or "mcp" in str(type(t)).lower():
                t_type = "mcp"
            all_tools.append({
                "name": t.name,
                "desc": t.description or "无描述",
                "active": getattr(t, "active", True),
                "type": t_type
            })
            
        # 根据名字去重（逻辑同 ToolSet）
        dedup = {}
        for tool in all_tools:
            name = tool["name"]
            if name not in dedup:
                dedup[name] = tool
            else:
                existing = dedup[name]
                if tool["active"] and not existing["active"]:
                    dedup[name] = tool
                elif tool["active"] == existing["active"]:
                    dedup[name] = tool
                    
        return sorted(list(dedup.values()), key=lambda x: x["name"].lower())

    async def set_tool_active(self, name: str, active: bool):
        llm_tools = self.context.provider_manager.llm_tools
        if active:
            from astrbot.core.star.star import star_map
            llm_tools.activate_llm_tool(name, star_map)
        else:
            llm_tools.deactivate_llm_tool(name)
        return True

class Main(star.Star):
    def __init__(self, context: star.Context, config: Any = None):
        super().__init__(context)
        self.perm_logic = PermissionManagerCommands(context)
        
        # 注册 Native Pages API
        context.register_web_api(f"/{PLUGIN_NAME}/plugins", self.api_list_plugins, ["GET"], "获取插件列表")
        context.register_web_api(f"/{PLUGIN_NAME}/plugin/<plugin_name>/commands", self.api_plugin_commands, ["GET"], "获取命令列表")
        context.register_web_api(f"/{PLUGIN_NAME}/command/<plugin_name>/<handler_name>/set-permission", self.api_set_perm, ["POST"], "设置权限")
        context.register_web_api(f"/{PLUGIN_NAME}/plugin/<plugin_name>/set-permission", self.api_batch_perm, ["POST"], "批量设置权限")
        context.register_web_api(f"/{PLUGIN_NAME}/command/<plugin_name>/<handler_name>/set-name", self.api_set_name, ["POST"], "修改名称")
        context.register_web_api(f"/{PLUGIN_NAME}/command/<plugin_name>/<handler_name>/set-aliases", self.api_set_aliases, ["POST"], "设置别名")
        
        # 新增 API
        context.register_web_api(f"/{PLUGIN_NAME}/commands/all", self.api_all_commands, ["GET"], "获取所有命令列表")
        context.register_web_api(f"/{PLUGIN_NAME}/plugin/<plugin_name>/logo", self.api_plugin_logo, ["GET"], "获取插件Logo")
        context.register_web_api(f"/{PLUGIN_NAME}/tools/all", self.api_all_tools, ["GET"], "获取所有函数工具列表")
        context.register_web_api(f"/{PLUGIN_NAME}/tools/<name>/set-active", self.api_set_tool_active, ["POST"], "设置函数工具激活状态")

        # 启动自动加载
        asyncio.create_task(self.auto_apply_permissions())

    async def auto_apply_permissions(self):
        # 稍微等下其他插件注册完毕
        await asyncio.sleep(3.0)
        try:
            await self.perm_logic.apply_all_permissions()
        except Exception as e:
            logger.error(f"[PermissionManager] 自动加载应用权限时发生错误: {e}")

    async def api_list_plugins(self):
        try:
            data = await self.perm_logic.get_all_plugins_api()
            return jsonify(data)
        except Exception as e:
            return jsonify({"success": False, "message": str(e)})

    async def api_plugin_commands(self, plugin_name):
        try:
            data = await self.perm_logic.get_plugin_commands_api(plugin_name)
            return jsonify(data)
        except Exception as e:
            return jsonify({"success": False, "message": str(e)})

    async def api_all_commands(self):
        try:
            data = await self.perm_logic.get_all_commands_api()
            return jsonify(data)
        except Exception as e:
            return jsonify({"success": False, "message": str(e)})

    async def api_plugin_logo(self, plugin_name):
        logo_path = None
        for plugin in star_map.values():
            if plugin.name == plugin_name and plugin.logo_path and os.path.exists(plugin.logo_path):
                logo_path = plugin.logo_path
                break
        if logo_path:
            return await send_file(logo_path)
        
        default_logo = "data/plugins/astrbot_plugin_permission-manager/logo.png"
        if os.path.exists(default_logo):
            return await send_file(default_logo)
        return jsonify({"success": False, "message": "No logo found"})

    
    async def api_all_tools(self):
        try:
            data = await self.perm_logic.get_all_tools_api()
            return jsonify(data)
        except Exception as e:
            return jsonify({"success": False, "message": str(e)})

    async def api_set_tool_active(self, name):
        try:
            req = await request.json
            active = req.get("active", True)
            await self.perm_logic.set_tool_active(name, active)
            return jsonify({"success": True})
        except Exception as e:
            return jsonify({"success": False, "message": str(e)})
    async def api_set_perm(self, plugin_name, handler_name):
        req = await request.json
        await self.perm_logic.set_command_permission(plugin_name, handler_name, req.get("permission"))
        return jsonify({"success": True})

    async def api_batch_perm(self, plugin_name):
        req = await request.json
        perm = req.get("permission")
        cmds = self.perm_logic._get_all_commands_by_plugin().get(plugin_name, [])
        for h, _, _, _ in cmds:
            await self.perm_logic.set_command_permission(plugin_name, h.handler_name, perm)
        return jsonify({"success": True})

    async def api_set_name(self, plugin_name, handler_name):
        req = await request.json
        new_name = req.get("name")
        alter_cmd_cfg = await sp.global_get("alter_cmd", {})
        plugin_cfg = alter_cmd_cfg.setdefault(plugin_name, {})
        plugin_cfg.setdefault(handler_name, {})["name"] = new_name
        await sp.global_put("alter_cmd", alter_cmd_cfg)

        handler = self.perm_logic._find_handler(plugin_name, handler_name)
        if handler:
            self.perm_logic._apply_command_identity(handler, name=new_name)

        return jsonify({"success": True})

    async def api_set_aliases(self, plugin_name, handler_name):
        req = await request.json
        aliases = req.get("aliases", [])
        if not isinstance(aliases, list):
            aliases = list(aliases) if aliases else []
        alter_cmd_cfg = await sp.global_get("alter_cmd", {})
        plugin_cfg = alter_cmd_cfg.setdefault(plugin_name, {})
        plugin_cfg.setdefault(handler_name, {})["aliases"] = aliases
        await sp.global_put("alter_cmd", alter_cmd_cfg)

        handler = self.perm_logic._find_handler(plugin_name, handler_name)
        if handler:
            self.perm_logic._apply_command_identity(handler, aliases=aliases)

        return jsonify({"success": True})

    @filter.command_group("perm")
    def perm(self): pass

    @filter.permission_type(filter.PermissionType.ADMIN)
    @perm.command("list")
    async def list_cmd(self, event: AstrMessageEvent):
        plugins = await self.perm_logic.get_all_plugins_api()
        msg = "📋 插件列表 (可在 WebUI 管理)：\n" + "\n".join([f"🔹 {p['name']} ({p['total_commands']} cmds)" for p in plugins])
        yield event.plain_result(msg)
