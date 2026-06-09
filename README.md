# astrbot_plugin_permission_manager

<div align="center">

_✨ AstrBot 原生权限管理插件 ✨_

[![License](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![AstrBot](https://img.shields.io/badge/AstrBot-4.24%2B-orange.svg)](https://github.com/Soulter/AstrBot)

</div>

## 🤝 介绍

批量权限管理插件，提供便捷的批量权限设置功能。已完全适配 AstrBot v4.24+ 原生 Page 页面系统，无需独立开启 Web 端口，直接集成在 AstrBot 管理面板中。

**主要特性：**
- ✅ **原生集成**：接入 AstrBot v4.24 Page 系统，直接在管理后台操作
- ✅ **批量操作**：一键批量设置整个插件的所有命令权限
- ✅ **可视化界面**：支持修改指令名、添加/删除别名、切换权限状态
- ✅ **完全兼容**：与原有的 `/alter_cmd` 配置完全同步
- ✅ **实时生效**：设置后立即生效，无需重启

## 📦 安装

直接在 AstrBot 的插件市场中搜索 `astrbot_plugin_permission-manager` 安装或更新即可。

## 🐔 使用说明

### 1. 网页后台管理 (推荐)

1. 进入 AstrBot 管理后台。
2. 点击“插件”页面，找到“指令编辑拓展”插件。
3. 点击插件卡片进入详情页，点击“权限管理”原生页面。
4. 在这里可以：
   - 搜索并查看所有插件及其命令。
   - 批量或单独设置命令权限（管理员/成员）。
   - 直接修改指令名称和别名。

### 2. 命令行使用

- `/perm list`: 列出所有已启用的插件及其命令数量。

## 💡 使用场景

- **全员禁言某插件**：一键将该插件所有指令设为 `admin`。
- **自定义指令名**：觉得默认指令太长？在界面里直接改成自己喜欢的。
- **添加快捷别名**：为常用指令添加简短别名。

## 📄 许可证

MIT License
