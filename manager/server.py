import functools
import os
import traceback
from typing import Dict, Any
from quart import (
    Quart, render_template, request, redirect, url_for, session, flash,
    Blueprint, current_app, jsonify
)
from astrbot.api import logger


admin_bp = Blueprint(
    "admin_bp",
    __name__,
    template_folder="templates",
    static_folder="static",
)


def create_app(secret_key: str, services: Dict[str, Any]):
    """
    创建并配置Quart应用实例。

    Args:
        secret_key: 用于session加密的密钥。
        services: 关键字参数，包含所有需要注入的服务实例。
    """
    app = Quart(__name__)
    app.secret_key = os.urandom(24)
    app.config["SECRET_LOGIN_KEY"] = secret_key

    # 将所有注入的服务实例存入app的配置中，供路由函数使用
    for service_name, service_instance in services.items():
        app.config[service_name.upper()] = service_instance

    app.register_blueprint(admin_bp, url_prefix="/admin")

    @app.route("/")
    def root():
        return redirect(url_for("admin_bp.index"))
    
    @app.route("/favicon.ico")
    def favicon():
        from quart import abort
        abort(404)
    
    # 添加全局错误处理器
    @app.errorhandler(404)
    async def handle_404_error(error):
        if not request.path.startswith('/admin/static/') and request.path != '/favicon.ico':
            logger.error(f"404 Not Found: {request.url} - {request.method}")
        
        if request.path.startswith('/admin/api/') and request.method in ['POST', 'PUT', 'DELETE', 'GET']:
            return {"success": False, "message": "API端点不存在"}, 404
        return "Not Found", 404
    
    @app.errorhandler(500)
    async def handle_500_error(error):
        logger.error(f"Internal Server Error: {error}")
        logger.error(traceback.format_exc())
        
        if request.path.startswith('/admin/api/') and request.method in ['POST', 'PUT', 'DELETE', 'GET']:
            return {"success": False, "message": "服务器内部错误"}, 500
        return "Internal Server Error", 500
    
    return app


def login_required(f):
    @functools.wraps(f)
    async def decorated_function(*args, **kwargs):
        if "logged_in" not in session:
            return redirect(url_for("admin_bp.login"))
        return await f(*args, **kwargs)
    return decorated_function


@admin_bp.route("/login", methods=["GET", "POST"])
async def login():
    if request.method == "POST":
        form = await request.form
        secret_key = current_app.config["SECRET_LOGIN_KEY"]
        if form.get("secret_key") == secret_key:
            session["logged_in"] = True
            session["is_admin"] = True
            await flash("登录成功！", "success")
            return redirect(url_for("admin_bp.index"))
        else:
            await flash("登录失败，请检查密钥！", "danger")
    return await render_template("login.html")


@admin_bp.route("/logout")
async def logout():
    session.pop("logged_in", None)
    await flash("你已成功登出。", "info")
    return redirect(url_for("admin_bp.login"))


@admin_bp.route("/")
@login_required
async def index():
    permission_service = current_app.config.get("PERMISSION_SERVICE")
    plugins = permission_service.get_all_plugins() if permission_service else []
    return await render_template("index.html", plugins=plugins)


@admin_bp.route("/plugin/<plugin_name>")
@login_required
async def plugin_detail(plugin_name: str):
    permission_service = current_app.config.get("PERMISSION_SERVICE")
    if not permission_service:
        await flash("权限服务未初始化", "danger")
        return redirect(url_for("admin_bp.index"))
    
    commands = await permission_service.get_plugin_commands(plugin_name)
    if commands is None:
        await flash(f"未找到插件: {plugin_name}", "danger")
        return redirect(url_for("admin_bp.index"))
    
    return await render_template("plugin_detail.html", plugin_name=plugin_name, commands=commands)


@admin_bp.route("/api/plugins", methods=["GET"])
@login_required
async def api_plugins():
    permission_service = current_app.config.get("PERMISSION_SERVICE")
    if not permission_service:
        return jsonify({"success": False, "message": "权限服务未初始化"}), 500
    
    plugins = permission_service.get_all_plugins()
    return jsonify({"success": True, "data": plugins})


@admin_bp.route("/api/plugin/<plugin_name>/commands", methods=["GET"])
@login_required
async def api_plugin_commands(plugin_name: str):
    permission_service = current_app.config.get("PERMISSION_SERVICE")
    if not permission_service:
        return jsonify({"success": False, "message": "权限服务未初始化"}), 500
    
    commands = await permission_service.get_plugin_commands(plugin_name)
    if commands is None:
        return jsonify({"success": False, "message": f"未找到插件: {plugin_name}"}), 404
    
    return jsonify({"success": True, "data": commands})


@admin_bp.route("/api/plugin/<plugin_name>/set-permission", methods=["POST"])
@login_required
async def api_set_plugin_permission(plugin_name: str):
    permission_service = current_app.config.get("PERMISSION_SERVICE")
    if not permission_service:
        return jsonify({"success": False, "message": "权限服务未初始化"}), 500
    
    data = await request.json
    permission = data.get("permission")
    
    if permission not in ["admin", "member"]:
        return jsonify({"success": False, "message": "权限类型错误，只能是 admin 或 member"}), 400
    
    result = await permission_service.set_plugin_permission(plugin_name, permission)
    if result["success"]:
        return jsonify({"success": True, "message": result["message"], "data": result})
    else:
        return jsonify({"success": False, "message": result["message"]}), 400


@admin_bp.route("/api/command/<plugin_name>/<handler_name>/set-permission", methods=["POST"])
@login_required
async def api_set_command_permission(plugin_name: str, handler_name: str):
    permission_service = current_app.config.get("PERMISSION_SERVICE")
    if not permission_service:
        return jsonify({"success": False, "message": "权限服务未初始化"}), 500
    
    data = await request.json
    permission = data.get("permission")
    
    if permission not in ["admin", "member"]:
        return jsonify({"success": False, "message": "权限类型错误，只能是 admin 或 member"}), 400
    
    result = await permission_service.set_command_permission(plugin_name, handler_name, permission)
    if result["success"]:
        return jsonify({"success": True, "message": result["message"]})
    else:
        return jsonify({"success": False, "message": result["message"]}), 400


@admin_bp.route("/api/command/<plugin_name>/<handler_name>/set-name", methods=["POST"])
@login_required
async def api_set_command_name(plugin_name: str, handler_name: str):
    permission_service = current_app.config.get("PERMISSION_SERVICE")
    if not permission_service:
        return jsonify({"success": False, "message": "权限服务未初始化"}), 500
    
    data = await request.json
    new_name = data.get("name")
    
    if not new_name:
        return jsonify({"success": False, "message": "新名称不能为空"}), 400
    
    result = await permission_service.set_command_name(plugin_name, handler_name, new_name)
    if result["success"]:
        return jsonify({"success": True, "message": result["message"]})
    else:
        return jsonify({"success": False, "message": result["message"]}), 400


@admin_bp.route("/api/command/<plugin_name>/<handler_name>/set-aliases", methods=["POST"])
@login_required
async def api_set_command_aliases(plugin_name: str, handler_name: str):
    permission_service = current_app.config.get("PERMISSION_SERVICE")
    if not permission_service:
        return jsonify({"success": False, "message": "权限服务未初始化"}), 500
    
    data = await request.json
    aliases = data.get("aliases", [])
    
    if not isinstance(aliases, list):
        return jsonify({"success": False, "message": "别名必须是列表格式"}), 400
    
    result = await permission_service.set_command_aliases(plugin_name, handler_name, aliases)
    if result["success"]:
        return jsonify({"success": True, "message": result["message"]})
    else:
        return jsonify({"success": False, "message": result["message"]}), 400

