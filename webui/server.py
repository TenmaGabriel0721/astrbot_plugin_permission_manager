from __future__ import annotations

import asyncio
from typing import Any, Callable

import uvicorn
from astrbot.api import logger

ASGIAppFactory = Callable[[], Any]


class WebUIServer:
    """
    权限管理 WebUI 服务包装器
    参考 LivingMemory 插件的 WebUI 启动逻辑，确保端口复用与优雅关闭。
    """

    def __init__(
        self,
        host: str,
        port: int,
        app_factory: ASGIAppFactory,
        startup_path: str = "/admin",
    ) -> None:
        self.host = str(host or "127.0.0.1")
        self.port = int(port)
        self._app_factory = app_factory
        self._startup_path = startup_path

        self._app: Any = None
        self._server: uvicorn.Server | None = None
        self._server_task: asyncio.Task | None = None

    async def start(self) -> None:
        """启动 WebUI 服务"""
        if self.is_running:
            logger.warning("PermissionManager WebUI 服务已在运行中")
            return

        self._app = self._app_factory()

        config = uvicorn.Config(
            app=self._app,
            host=self.host,
            port=self.port,
            log_level="info",
            loop="asyncio",
            lifespan="on",
        )
        self._server = uvicorn.Server(config)
        self._server_task = asyncio.create_task(self._server.serve())

        # 等待服务启动
        for _ in range(50):
            if getattr(self._server, "started", False):
                logger.info(
                    "PermissionManager WebUI 已启动: http://%s:%s%s",
                    self._display_host,
                    self.port,
                    self._startup_path,
                )
                return

            if self._server_task.done():
                error = self._server_task.exception()
                raise RuntimeError(f"WebUI 启动失败: {error}") from error

            await asyncio.sleep(0.1)

        logger.warning("PermissionManager WebUI 启动耗时较长，仍在后台启动中")

    async def stop(self) -> None:
        """停止 WebUI 服务"""
        if not self.is_running:
            logger.info("PermissionManager WebUI 服务未运行，无需停止")
            return

        if self._server:
            self._server.should_exit = True

        if self._server_task:
            try:
                await self._server_task
            finally:
                self._server_task = None

        self._server = None
        self._app = None
        logger.info("PermissionManager WebUI 已停止")

    @property
    def is_running(self) -> bool:
        return self._server_task is not None and not self._server_task.done()

    @property
    def _display_host(self) -> str:
        if self.host in {"0.0.0.0", ""}:
            return "127.0.0.1"
        return self.host

