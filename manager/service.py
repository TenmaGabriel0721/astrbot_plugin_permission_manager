"""权限管理服务类，用于 Web UI"""
from typing import Dict, List, Optional, Any
from astrbot.core.star.star_handler import star_handlers_registry, StarHandlerMetadata
from astrbot.core.star.star import star_map
from astrbot.core.star.filter.command import CommandFilter
from astrbot.core.star.filter.command_group import CommandGroupFilter
from astrbot.core.star.filter.permission import PermissionTypeFilter, PermissionType
from astrbot.api import sp


class PermissionService:
    """权限管理服务类"""
    
    def __init__(self):
        pass
    
    def _get_all_commands_by_plugin(self) -> Dict[str, List[tuple]]:
        """
        获取所有插件及其命令列表
        返回: {插件名: [(handler, 命令名, 命令类型, 是否是指令组), ...]}
        """
        plugin_commands = {}
        
        for handler in star_handlers_registry:
            assert isinstance(handler, StarHandlerMetadata)
            if handler.handler_module_path not in star_map:
                continue
            
            plugin = star_map[handler.handler_module_path]
            if not plugin.activated:
                continue
            
            if plugin.name not in plugin_commands:
                plugin_commands[plugin.name] = []
            
            # 检查命令过滤器
            for event_filter in handler.event_filters:
                if isinstance(event_filter, CommandFilter):
                    plugin_commands[plugin.name].append(
                        (handler, event_filter.command_name, "command", False)
                    )
                    break
                elif isinstance(event_filter, CommandGroupFilter):
                    plugin_commands[plugin.name].append(
                        (handler, event_filter.group_name, "command_group", True)
                    )
                    break
        
        return plugin_commands
    
    def get_all_plugins(self) -> List[Dict[str, Any]]:
        """获取所有插件列表"""
        plugin_commands = self._get_all_commands_by_plugin()
        
        plugins = []
        for plugin_name, commands in plugin_commands.items():
            command_count = len([c for c in commands if c[2] == "command"])
            group_count = len([c for c in commands if c[3]])
            
            plugins.append({
                "name": plugin_name,
                "command_count": command_count,
                "group_count": group_count,
                "total_commands": len(commands)
            })
        
        return plugins
    
    async def get_plugin_commands(self, plugin_name: str) -> Optional[Dict[str, Any]]:
        """获取指定插件的所有命令"""
        plugin_commands = self._get_all_commands_by_plugin()
        
        if plugin_name not in plugin_commands:
            return None
        
        commands = plugin_commands[plugin_name]
        alter_cmd_cfg = await sp.global_get("alter_cmd", {})
        plugin_cfg = alter_cmd_cfg.get(plugin_name, {})
        
        command_list = []
        group_list = []
        
        for handler, cmd_name, cmd_type, is_group in commands:
            current_perm = plugin_cfg.get(handler.handler_name, {}).get("permission", "未设置")
            if current_perm == "未设置":
                # 检查handler中是否有权限过滤器
                for event_filter in handler.event_filters:
                    if isinstance(event_filter, PermissionTypeFilter):
                        if event_filter.permission_type == PermissionType.ADMIN:
                            current_perm = "admin"
                        else:
                            current_perm = "member"
                        break
            
            # 获取别名信息
            cmd_cfg = plugin_cfg.get(handler.handler_name, {})
            # 检查配置中是否明确设置了别名（包括空列表）
            if "aliases" in cmd_cfg:
                aliases = cmd_cfg.get("aliases", [])
            else:
                # 如果配置中没有别名设置，尝试从过滤器中获取
                aliases = []
                for event_filter in handler.event_filters:
                    if isinstance(event_filter, (CommandFilter, CommandGroupFilter)):
                        if event_filter.alias:
                            aliases = list(event_filter.alias)
                        break
            
            # 确保 aliases 是列表类型
            if not isinstance(aliases, list):
                aliases = list(aliases) if aliases else []
            
            # 获取命令名（可能被修改过）
            display_name = plugin_cfg.get(handler.handler_name, {}).get("name", cmd_name)
            
            info = {
                "name": display_name,
                "original_name": cmd_name,
                "type": cmd_type,
                "handler": handler.handler_name,
                "permission": current_perm,
                "aliases": aliases,
                "is_group": is_group,
                "desc": handler.desc or ""
            }
            
            if is_group:
                group_list.append(info)
            else:
                command_list.append(info)
        
        return {
            "commands": command_list,
            "groups": group_list
        }
    
    async def set_plugin_permission(self, plugin_name: str, permission: str) -> Dict[str, Any]:
        """批量设置插件所有命令的权限"""
        plugin_commands = self._get_all_commands_by_plugin()
        if plugin_name not in plugin_commands:
            return {"success": False, "message": f"未找到插件: {plugin_name}"}
        
        if permission not in ["admin", "member"]:
            return {"success": False, "message": "权限类型错误，只能是 admin 或 member"}
        
        # 更新配置
        alter_cmd_cfg = await sp.global_get("alter_cmd", {})
        plugin_cfg = alter_cmd_cfg.get(plugin_name, {})
        
        success_count = 0
        total_count = 0
        
        for handler, cmd_name, cmd_type, is_group in plugin_commands[plugin_name]:
            total_count += 1
            cmd_cfg = plugin_cfg.get(handler.handler_name, {})
            cmd_cfg["permission"] = permission
            plugin_cfg[handler.handler_name] = cmd_cfg
            
            # 更新handler中的权限过滤器
            found_permission_filter = False
            for event_filter in handler.event_filters:
                if isinstance(event_filter, PermissionTypeFilter):
                    if permission == "admin":
                        event_filter.permission_type = PermissionType.ADMIN
                    else:
                        event_filter.permission_type = PermissionType.MEMBER
                    found_permission_filter = True
                    break
            
            if not found_permission_filter:
                handler.event_filters.append(
                    PermissionTypeFilter(
                        PermissionType.ADMIN if permission == "admin" else PermissionType.MEMBER
                    )
                )
            
            success_count += 1
        
        alter_cmd_cfg[plugin_name] = plugin_cfg
        await sp.global_put("alter_cmd", alter_cmd_cfg)
        
        return {
            "success": True,
            "message": f"成功设置 {success_count}/{total_count} 个命令的权限",
            "success_count": success_count,
            "total_count": total_count
        }
    
    async def set_command_permission(self, plugin_name: str, handler_name: str, permission: str) -> Dict[str, Any]:
        """设置单个命令的权限"""
        plugin_commands = self._get_all_commands_by_plugin()
        if plugin_name not in plugin_commands:
            return {"success": False, "message": f"未找到插件: {plugin_name}"}
        
        if permission not in ["admin", "member"]:
            return {"success": False, "message": "权限类型错误，只能是 admin 或 member"}
        
        # 查找handler
        found_handler = None
        for handler, cmd_name, cmd_type, is_group in plugin_commands[plugin_name]:
            if handler.handler_name == handler_name:
                found_handler = handler
                break
        
        if not found_handler:
            return {"success": False, "message": f"未找到命令处理器: {handler_name}"}
        
        # 更新配置
        alter_cmd_cfg = await sp.global_get("alter_cmd", {})
        plugin_cfg = alter_cmd_cfg.get(plugin_name, {})
        cmd_cfg = plugin_cfg.get(handler_name, {})
        cmd_cfg["permission"] = permission
        plugin_cfg[handler_name] = cmd_cfg
        alter_cmd_cfg[plugin_name] = plugin_cfg
        await sp.global_put("alter_cmd", alter_cmd_cfg)
        
        # 更新handler中的权限过滤器
        found_permission_filter = False
        for event_filter in found_handler.event_filters:
            if isinstance(event_filter, PermissionTypeFilter):
                if permission == "admin":
                    event_filter.permission_type = PermissionType.ADMIN
                else:
                    event_filter.permission_type = PermissionType.MEMBER
                found_permission_filter = True
                break
        
        if not found_permission_filter:
            found_handler.event_filters.append(
                PermissionTypeFilter(
                    PermissionType.ADMIN if permission == "admin" else PermissionType.MEMBER
                )
            )
        
        return {"success": True, "message": "权限设置成功"}
    
    async def set_command_name(self, plugin_name: str, handler_name: str, new_name: str) -> Dict[str, Any]:
        """设置命令名或指令组名"""
        plugin_commands = self._get_all_commands_by_plugin()
        if plugin_name not in plugin_commands:
            return {"success": False, "message": f"未找到插件: {plugin_name}"}
        
        # 查找handler
        found_handler = None
        for handler, cmd_name, cmd_type, is_group in plugin_commands[plugin_name]:
            if handler.handler_name == handler_name:
                found_handler = handler
                break
        
        if not found_handler:
            return {"success": False, "message": f"未找到命令处理器: {handler_name}"}
        
        # 更新配置
        alter_cmd_cfg = await sp.global_get("alter_cmd", {})
        plugin_cfg = alter_cmd_cfg.get(plugin_name, {})
        cmd_cfg = plugin_cfg.get(handler_name, {})
        cmd_cfg["name"] = new_name
        plugin_cfg[handler_name] = cmd_cfg
        alter_cmd_cfg[plugin_name] = plugin_cfg
        await sp.global_put("alter_cmd", alter_cmd_cfg)
        
        # 更新handler中的过滤器
        for event_filter in found_handler.event_filters:
            if isinstance(event_filter, CommandFilter):
                event_filter.command_name = new_name
                event_filter._cmpl_cmd_names = None
                break
            elif isinstance(event_filter, CommandGroupFilter):
                event_filter.group_name = new_name
                event_filter._cmpl_cmd_names = None
                break
        
        return {"success": True, "message": f"成功将命令名修改为 {new_name}"}
    
    async def set_command_aliases(self, plugin_name: str, handler_name: str, aliases: List[str]) -> Dict[str, Any]:
        """设置命令别名列表"""
        plugin_commands = self._get_all_commands_by_plugin()
        if plugin_name not in plugin_commands:
            return {"success": False, "message": f"未找到插件: {plugin_name}"}
        
        # 确保 aliases 是一个列表
        if not isinstance(aliases, list):
            aliases = list(aliases) if aliases else []
        
        # 查找handler
        found_handler = None
        for handler, cmd_name, cmd_type, is_group in plugin_commands[plugin_name]:
            if handler.handler_name == handler_name:
                found_handler = handler
                break
        
        if not found_handler:
            return {"success": False, "message": f"未找到命令处理器: {handler_name}"}
        
        # 更新配置
        alter_cmd_cfg = await sp.global_get("alter_cmd", {})
        plugin_cfg = alter_cmd_cfg.get(plugin_name, {})
        cmd_cfg = plugin_cfg.get(handler_name, {})
        # 确保保存的是列表，即使是空列表也要保存
        cmd_cfg["aliases"] = aliases if aliases else []
        plugin_cfg[handler_name] = cmd_cfg
        alter_cmd_cfg[plugin_name] = plugin_cfg
        await sp.global_put("alter_cmd", alter_cmd_cfg)
        
        # 更新handler中的过滤器
        for event_filter in found_handler.event_filters:
            if isinstance(event_filter, CommandFilter):
                event_filter.alias = set(aliases) if aliases else set()
                event_filter._cmpl_cmd_names = None
                break
            elif isinstance(event_filter, CommandGroupFilter):
                event_filter.alias = set(aliases) if aliases else set()
                event_filter._cmpl_cmd_names = None
                break
        
        return {"success": True, "message": f"成功设置别名: {', '.join(aliases) if aliases else '无'}"}

