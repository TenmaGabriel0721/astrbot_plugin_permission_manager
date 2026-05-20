import asyncio
from typing import Any, Dict, List, Optional, Tuple

import astrbot.api.star as star
import astrbot.api.event.filter as filter
from astrbot.api.event import AstrMessageEvent, MessageChain
from astrbot.api import sp, logger
from astrbot.core.star.star_handler import star_handlers_registry, StarHandlerMetadata
from astrbot.core.star.star import star_map
from astrbot.core.star.filter.command import CommandFilter
from astrbot.core.star.filter.command_group import CommandGroupFilter
from astrbot.core.star.filter.permission import PermissionTypeFilter, PermissionType
from astrbot.core.utils.command_parser import CommandParserMixin
from quart import jsonify, request

# 为内置指令做额外判断
import sys

PLUGIN_NAME = "astrbot_plugin_permission-manager"

class PermissionManagerCommands(CommandParserMixin):
    """批量权限管理逻辑类"""
    def __init__(self, context: star.Context):
        self.context = context

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
            plugins.append({
                "name": name,
                "command_count": len([c for c in cmds if c[2] == "command"]),
                "group_count": len([c for c in cmds if c[3]]),
                "total_commands": len(cmds)
            })
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
        return {"commands": command_list, "groups": group_list}

    async def set_command_permission(self, plugin_name, handler_name, permission):
        alter_cmd_cfg = await sp.global_get("alter_cmd", {})
        plugin_cfg = alter_cmd_cfg.setdefault(plugin_name, {})
        cmd_cfg = plugin_cfg.setdefault(handler_name, {})
        cmd_cfg["permission"] = permission
        await sp.global_put("alter_cmd", alter_cmd_cfg)
        
        for handler in star_handlers_registry:
            if handler.handler_name == handler_name:
                target = PermissionType.ADMIN if permission == "admin" else PermissionType.MEMBER
                found = False
                for f in handler.event_filters:
                    if isinstance(f, PermissionTypeFilter):
                        f.permission_type = target; found = True; break
                if not found: handler.event_filters.append(PermissionTypeFilter(target))
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
            
            if permission in ["admin", "member"]:
                target = PermissionType.ADMIN if permission == "admin" else PermissionType.MEMBER
                found = False
                for f in handler.event_filters:
                    if isinstance(f, PermissionTypeFilter):
                        f.permission_type = target; found = True; break
                if not found: 
                    handler.event_filters.append(PermissionTypeFilter(target))
                applied_count += 1
                
        logger.info(f"[PermissionManager] 成功自动应用了 {applied_count} 个指令的权限配置！")

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
        return jsonify({"success": True})

    async def api_set_aliases(self, plugin_name, handler_name):
        req = await request.json
        aliases = req.get("aliases", [])
        alter_cmd_cfg = await sp.global_get("alter_cmd", {})
        plugin_cfg = alter_cmd_cfg.setdefault(plugin_name, {})
        plugin_cfg.setdefault(handler_name, {})["aliases"] = aliases
        await sp.global_put("alter_cmd", alter_cmd_cfg)
        return jsonify({"success": True})

    @filter.command_group("perm")
    def perm(self): pass

    @filter.permission_type(filter.PermissionType.ADMIN)
    @perm.command("list")
    async def list_cmd(self, event: AstrMessageEvent):
        plugins = await self.perm_logic.get_all_plugins_api()
        msg = "📋 插件列表 (可在 WebUI 管理)：\n" + "\n".join([f"🔹 {p['name']} ({p['total_commands']} cmds)" for p in plugins])
        yield event.plain_result(msg)
