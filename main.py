import asyncio
import base64
import math
import mimetypes
import os
import time
from io import BytesIO
from typing import Any

from quart import jsonify, request, send_file

import astrbot.api.event.filter as filter
import astrbot.api.star as star
from astrbot.api import logger, sp
from astrbot.api.event import AstrMessageEvent, MessageChain
from astrbot.core.star.filter import HandlerFilter
from astrbot.core.star.filter.command import CommandFilter
from astrbot.core.star.filter.command_group import CommandGroupFilter
from astrbot.core.star.filter.permission import PermissionType, PermissionTypeFilter
from astrbot.core.star.session_plugin_manager import SessionPluginManager
from astrbot.core.star.star import star_map
from astrbot.core.star.star_handler import StarHandlerMetadata, star_handlers_registry
from astrbot.core.utils.command_parser import CommandParserMixin

PLUGIN_NAME = "astrbot_plugin_permission_manager"
GLOBAL_COOLDOWN_HANDLER_PRIORITY = 9_223_372_036_854_775_807

# The AstrBot core currently exposes only ADMIN/MEMBER, and MEMBER is a
# pass-through filter.  Keep the plugin's richer access levels separate from
# those core enum values and use a compatibility field when persisting them in
# ``alter_cmd`` (the core still reads the legacy ``permission`` key).
PERMISSION_FRAMEWORK_ADMIN = "framework_admin"
PERMISSION_GROUP_ADMIN = "group_admin"
PERMISSION_EVERYONE = "everyone"
PERMISSION_LEVELS = {
    PERMISSION_FRAMEWORK_ADMIN,
    PERMISSION_GROUP_ADMIN,
    PERMISSION_EVERYONE,
}
PERMISSION_CONFIG_KEY = "permission_level"
LEGACY_PERMISSION_KEY = "permission"
PRIVATE_CHAT_CONFIG_KEY = "private_chat_enabled"
DEFAULT_PRIVATE_CHAT_DENIED_MESSAGE = "该指令不支持私聊使用。"
DEFAULT_GROUP_ADMIN_DENIED_MESSAGE = (
    "该指令仅限群主、群管理员或 AstrBot 框架管理员使用。"
)
GROUP_ROLE_CACHE_TTL = 15.0
ORIGINAL_PERMISSION_FILTERS_KEY = (
    "_astrbot_permission_manager_original_permission_filters"
)
FALLBACK_PERMISSION_FILTER_ATTR = "permission_manager_fallback_filter"
BLOCKED_COMMANDS_EXTRA_KEY = "permission_manager_blocked_commands"
BLOCKED_CALL_LLM_ORIGINAL_EXTRA_KEY = "permission_manager_original_call_llm"


class WakeCommandFilter(filter.CustomFilter):
    """Activate the cooldown gate only for messages that can wake AstrBot."""

    def filter(self, event: AstrMessageEvent, cfg: Any) -> bool:
        """Check whether an event is eligible for the cooldown gate.

        Args:
            event: Incoming AstrBot message event.
            cfg: AstrBot configuration passed by the filter pipeline.

        Returns:
            True when AstrBot's waking stage marked the event as a command or
            wake-up message.
        """
        return bool(getattr(event, "is_at_or_wake_command", False))


class ManagedPermissionCompatFilter(PermissionTypeFilter):
    """Always-pass native filter used as an /alter_cmd compatibility sentinel.

    AstrBot's native command manager searches for ``PermissionTypeFilter`` and
    mutates it in place.  Keeping this harmless sentinel on a managed handler
    prevents the core from inserting a real native filter ahead of our custom
    gate, while still allowing us to observe an external admin/member change.
    """

    managed_by_permission_manager = True
    permission_manager_compat_filter = True

    def __init__(self, permission: str) -> None:
        permission_type = (
            PermissionType.ADMIN
            if permission in {PERMISSION_FRAMEWORK_ADMIN, PERMISSION_GROUP_ADMIN}
            else PermissionType.MEMBER
        )
        super().__init__(permission_type, raise_error=False)
        self._native_baseline_permission_type = permission_type

    def native_override(self) -> str | None:
        if self.permission_type != self._native_baseline_permission_type:
            return (
                PERMISSION_FRAMEWORK_ADMIN
                if self.permission_type == PermissionType.ADMIN
                else PERMISSION_EVERYONE
            )
        return None

    def filter(self, event: AstrMessageEvent, cfg: Any) -> bool:
        return True


class ManagedCommandAccessFilter(HandlerFilter):
    """Synchronous, fail-closed access check attached to each command.

    The central gate can be disabled by AstrBot's per-session plugin settings,
    so it must not be the only authorization boundary.  This filter handles
    framework admins, private-chat policy, and group roles available directly
    on the incoming event.  Unknown group roles are denied first and may be
    resolved asynchronously by the high-priority gate when that gate is active.
    """

    managed_by_permission_manager = True

    def __init__(
        self,
        handler: StarHandlerMetadata,
        permission: str,
        context: star.Context,
        plugin_config: Any,
        group_role_cache: dict[str, tuple[float, str | None, set[str]]],
        permission_resolver: Any = None,
        private_chat_resolver: Any = None,
        private_chat_enabled: bool = True,
    ) -> None:
        self.handler = handler
        self.context = context
        self.plugin_config = plugin_config
        self.group_role_cache = group_role_cache
        self.permission_resolver = permission_resolver
        self.private_chat_resolver = private_chat_resolver
        self.private_chat_enabled = private_chat_enabled
        self.permission_level = permission

    @staticmethod
    def _legacy_permission_type(permission: str) -> PermissionType:
        # group_admin intentionally fails closed to framework-admin-only when
        # this plugin is unavailable or still starting.
        if permission in {PERMISSION_FRAMEWORK_ADMIN, PERMISSION_GROUP_ADMIN}:
            return PermissionType.ADMIN
        return PermissionType.MEMBER

    def update(self, permission: str, plugin_config: Any) -> None:
        self.permission_level = permission
        self.plugin_config = plugin_config

    @staticmethod
    def _coerce_bool(value: Any) -> bool | None:
        if isinstance(value, bool):
            return value
        if isinstance(value, (int, float)):
            return value != 0
        if isinstance(value, str):
            normalized = value.strip().lower()
            if normalized in {"1", "true", "yes", "on", "开启", "是"}:
                return True
            if normalized in {"0", "false", "no", "off", "关闭", "否"}:
                return False
        return None

    @classmethod
    def _get_bool(cls, config: Any, key: str, default: bool) -> bool:
        try:
            value = config.get(key, default)
        except Exception:
            return default
        parsed = cls._coerce_bool(value)
        return default if parsed is None else parsed

    def _is_framework_admin(self, event: AstrMessageEvent) -> bool:
        if event.is_admin():
            return True
        try:
            admin_ids = self.context.get_config().get("admins_id", [])
        except Exception:
            admin_ids = []
        if isinstance(admin_ids, (str, int)):
            admin_ids = [admin_ids]
        if not isinstance(admin_ids, (list, tuple, set)):
            admin_ids = []
        sender_id = str(event.get_sender_id() or "").strip()
        return bool(sender_id) and sender_id in {
            str(admin_id).strip() for admin_id in admin_ids if str(admin_id).strip()
        }

    def _record_block(
        self,
        event: AstrMessageEvent,
        reason: str,
    ) -> None:
        blocked = event.get_extra(BLOCKED_COMMANDS_EXTRA_KEY)
        if not isinstance(blocked, dict):
            blocked = {}
            event.set_extra(BLOCKED_COMMANDS_EXTRA_KEY, blocked)
        if event.get_extra(BLOCKED_CALL_LLM_ORIGINAL_EXTRA_KEY) is None:
            event.set_extra(
                BLOCKED_CALL_LLM_ORIGINAL_EXTRA_KEY,
                bool(getattr(event, "call_llm", False)),
            )
        parsed_params = event.get_extra("parsed_params", {})
        blocked[self.handler.handler_full_name] = {
            "handler": self.handler,
            "parsed_params": (
                dict(parsed_params) if isinstance(parsed_params, dict) else {}
            ),
            "reason": reason,
        }
        # Even if the central gate is disabled for this session, a rejected
        # command must not fall through to the default LLM.
        event.should_call_llm(True)

    def _sync_group_access(self, event: AstrMessageEvent) -> tuple[bool, str]:
        if event.is_private_chat() or not event.get_group_id():
            return False, "group_admin_permission"

        raw_role = Main._extract_raw_group_role(event)
        # An adapter-provided explicit member role is authoritative. Do not
        # let stale group metadata or a cache list the sender as an admin.
        if raw_role == "member":
            return False, "group_admin_permission"
        if raw_role in {"owner", "admin"}:
            return True, ""

        sender_id = str(event.get_sender_id() or "").strip()
        current_group = getattr(event.message_obj, "group", None)
        owner_id, admin_ids = Main._group_identity(current_group)
        # If no explicit role was supplied, use the normalized group identity
        # carried by the message as the next-best local source.
        if sender_id and sender_id == owner_id:
            return True, ""
        if sender_id and sender_id in admin_ids:
            return True, ""
        # A non-empty normalized administrator list is complete enough for a
        # synchronous denial.  Several adapters expose ``group_admins=[]`` on
        # the incoming message even though ``event.get_group()`` can return the
        # real list, so an empty list must continue to the async lookup.
        if admin_ids:
            return False, "group_admin_permission"

        cache_key = Main._get_cooldown_scope(event)
        cached = self.group_role_cache.get(cache_key)
        now = time.monotonic()
        if cached and cached[0] > now:
            _, cached_owner, cached_admins = cached
            return bool(
                sender_id and (sender_id == cached_owner or sender_id in cached_admins)
            ), "group_admin_permission"
        return False, "group_lookup"

    @staticmethod
    def _handler_matches_command(
        handler: StarHandlerMetadata,
        event: AstrMessageEvent,
    ) -> bool:
        """Detect a command before CommandFilter validates its parameters."""
        if not getattr(event, "is_at_or_wake_command", False):
            return False
        message = " ".join(str(event.get_message_str() or "").strip().split())
        if not message:
            return False
        for event_filter in handler.event_filters:
            if isinstance(event_filter, CommandFilter):
                names = event_filter.get_complete_command_names()
                if any(
                    message == name or message.startswith(f"{name} ") for name in names
                ):
                    return True
            elif isinstance(event_filter, CommandGroupFilter):
                names = event_filter.get_complete_command_names()
                if any(
                    message == name or message.startswith(f"{name} ") for name in names
                ):
                    return True
        return False

    def _matches_command(self, event: AstrMessageEvent) -> bool:
        return self._handler_matches_command(self.handler, event)

    def filter(self, event: AstrMessageEvent, cfg: Any) -> bool:
        if not self._matches_command(event):
            return True

        permission = self.permission_level
        if self.permission_resolver is not None:
            try:
                resolved = self.permission_resolver(self.handler)
                if resolved in PERMISSION_LEVELS:
                    permission = resolved
            except Exception:
                # The synchronous filter must remain fail-closed if a live
                # resolver is unavailable during plugin reload.
                permission = self.permission_level

        if event.is_private_chat():
            private_chat_enabled = self.private_chat_enabled
            if self.private_chat_resolver is not None:
                try:
                    private_chat_enabled = bool(
                        self.private_chat_resolver(self.handler),
                    )
                except Exception:
                    # Keep the last applied value if configuration cannot be
                    # resolved during a reload race.
                    private_chat_enabled = self.private_chat_enabled
            if not private_chat_enabled:
                self._record_block(event, "private")
                return False

        if permission == PERMISSION_EVERYONE:
            return True

        framework_admin = self._is_framework_admin(event)
        if permission == PERMISSION_FRAMEWORK_ADMIN:
            if framework_admin:
                return True
            self._record_block(event, "framework_admin_permission")
            return False

        if permission == PERMISSION_GROUP_ADMIN:
            if framework_admin:
                return True
            allowed, reason = self._sync_group_access(event)
            if allowed:
                return True
            self._record_block(event, reason)
            return False

        self._record_block(event, "permission")
        return False


class PermissionManagerCommands(CommandParserMixin):
    """批量权限管理逻辑类"""

    def __init__(
        self,
        context: star.Context,
        plugin_config: Any = None,
        group_role_cache: dict[str, tuple[float, str | None, set[str]]] | None = None,
    ):
        self.context = context
        self.plugin_config = plugin_config or {}
        self.group_role_cache = group_role_cache if group_role_cache is not None else {}
        self._logo_data_cache: dict[str, tuple[int, int, str]] = {}
        # Effective levels are kept by handler full name so the event gate can
        # make a decision without reading the database for every message.
        self._permission_levels: dict[str, str] = {}
        self._stored_permission_config: dict[str, dict[str, dict[str, Any]]] = {}
        self._permission_config_loaded = False

    @staticmethod
    def normalize_permission(
        permission: Any,
        default: str = PERMISSION_EVERYONE,
    ) -> str:
        """Normalize current and historical permission values.

        ``admin`` and ``member`` are the values used by AstrBot's built-in
        command manager.  In the old plugin UI ``member`` and ``everyone``
        were effectively identical, so upgrading an old ``member`` entry to
        ``everyone`` avoids unexpectedly tightening access.
        """

        value = str(permission or "").strip().lower()
        aliases = {
            "admin": PERMISSION_FRAMEWORK_ADMIN,
            "framework_admin": PERMISSION_FRAMEWORK_ADMIN,
            "framework-admin": PERMISSION_FRAMEWORK_ADMIN,
            "仅管理员": PERMISSION_FRAMEWORK_ADMIN,
            "member": PERMISSION_EVERYONE,
            "普通": PERMISSION_EVERYONE,
            "普通及以上": PERMISSION_EVERYONE,
            "everyone": PERMISSION_EVERYONE,
            "all": PERMISSION_EVERYONE,
            "group_admin": PERMISSION_GROUP_ADMIN,
            "group-admin": PERMISSION_GROUP_ADMIN,
            "group_member_admin": PERMISSION_GROUP_ADMIN,
            "群主及管理员": PERMISSION_GROUP_ADMIN,
            "群主/群管理员及框架管理员": PERMISSION_GROUP_ADMIN,
        }
        normalized = aliases.get(value, value)
        return normalized if normalized in PERMISSION_LEVELS else default

    @staticmethod
    def _is_command_handler(handler: StarHandlerMetadata) -> bool:
        return any(
            isinstance(event_filter, (CommandFilter, CommandGroupFilter))
            for event_filter in handler.event_filters
        )

    @staticmethod
    def _permission_from_filter(permission_filter: PermissionTypeFilter) -> str:
        return (
            PERMISSION_FRAMEWORK_ADMIN
            if permission_filter.permission_type == PermissionType.ADMIN
            else PERMISSION_EVERYONE
        )

    @classmethod
    def _native_permission_override(
        cls,
        handler: StarHandlerMetadata,
        *,
        include_original: bool = False,
    ) -> str | None:
        """Read a native AstrBot permission filter when one is present.

        The permission manager replaces the native filter with its richer
        access filter.  AstrBot's ``/alter_cmd`` command can subsequently add
        a new native filter at runtime, though, so this lookup must inspect
        the live handler on every authorization decision.  ``include_original``
        is used only when determining the handler's initial/default level;
        the saved filters are not treated as an external runtime override.
        """

        # Once this manager owns a handler, the compatibility sentinel is the
        # only native permission filter that should be considered.  AstrBot's
        # command editor normally mutates that sentinel in place; an unrelated
        # PermissionTypeFilter can nevertheless appear ahead of our filters
        # during a reload/startup race.  Treating that stale filter as an
        # override would silently downgrade ``group_admin`` to
        # ``framework_admin`` (or make an ``everyone`` command disappear).
        # Pre-compute ownership so the order of filters cannot affect this
        # decision.
        managed_handler = any(
            isinstance(
                event_filter,
                (ManagedPermissionCompatFilter, ManagedCommandAccessFilter),
            )
            for event_filter in handler.event_filters
        )

        if managed_handler:
            for event_filter in handler.event_filters:
                if isinstance(event_filter, ManagedPermissionCompatFilter):
                    override = event_filter.native_override()
                    if override is not None or not include_original:
                        return override
                    break

            # A command may have had a native ADMIN decorator before this
            # manager took ownership.  It is not a live override, but it is
            # still the correct default when no persisted permission exists.
            if not include_original:
                return None
            original_filters = handler.extras_configs.get(
                ORIGINAL_PERMISSION_FILTERS_KEY,
            )
            if isinstance(original_filters, list):
                for _, event_filter in original_filters:
                    if isinstance(event_filter, PermissionTypeFilter):
                        return cls._permission_from_filter(event_filter)
            return None

        for event_filter in handler.event_filters:
            if isinstance(event_filter, ManagedPermissionCompatFilter):
                override = event_filter.native_override()
                if override is not None:
                    return override
                continue
            if isinstance(event_filter, ManagedCommandAccessFilter):
                continue
            if (
                isinstance(event_filter, PermissionTypeFilter)
                and not getattr(event_filter, "managed_by_permission_manager", False)
                and not getattr(event_filter, FALLBACK_PERMISSION_FILTER_ATTR, False)
            ):
                return cls._permission_from_filter(event_filter)

        if include_original:
            original_filters = handler.extras_configs.get(
                ORIGINAL_PERMISSION_FILTERS_KEY,
            )
            if isinstance(original_filters, list):
                for _, event_filter in original_filters:
                    if (
                        isinstance(event_filter, PermissionTypeFilter)
                        and not getattr(
                            event_filter,
                            "managed_by_permission_manager",
                            False,
                        )
                        and not getattr(
                            event_filter,
                            FALLBACK_PERMISSION_FILTER_ATTR,
                            False,
                        )
                    ):
                        return cls._permission_from_filter(event_filter)
        return None

    @classmethod
    def _native_permission_level(cls, handler: StarHandlerMetadata) -> str:
        """Infer a level from a handler before plugin configuration exists."""

        return (
            cls._native_permission_override(handler, include_original=True)
            or PERMISSION_EVERYONE
        )

    @staticmethod
    def _primary_command_filter(
        handler: StarHandlerMetadata,
    ) -> CommandFilter | CommandGroupFilter | None:
        for event_filter in handler.event_filters:
            if isinstance(event_filter, (CommandFilter, CommandGroupFilter)):
                return event_filter
        return None

    @classmethod
    def _find_parent_group_handler(
        cls,
        handler: StarHandlerMetadata,
    ) -> StarHandlerMetadata | None:
        """Find the command-group handler that owns a sub-command.

        AstrBot executes a group handler and its child handler separately in
        the waking stage.  A permission configured on the group therefore
        needs an explicit inheritance relationship; relying on the native
        ``PermissionTypeFilter`` leaves child commands open to everyone.
        """

        command_filter = cls._primary_command_filter(handler)
        if command_filter is None:
            return None

        direct_parent_filter = (
            command_filter.parent_group
            if isinstance(command_filter, CommandGroupFilter)
            else None
        )

        # Prefer the object relationship built by AstrBot's decorators.  It is
        # unaffected by aliases and command renames, and it also covers nested
        # CommandGroupFilter instances (which do not expose
        # ``parent_command_names`` like leaf CommandFilter instances do).
        for candidate in star_handlers_registry:
            if candidate is handler:
                continue
            if candidate.handler_module_path != handler.handler_module_path:
                continue
            candidate_filter = cls._primary_command_filter(candidate)
            if not isinstance(candidate_filter, CommandGroupFilter):
                continue
            if candidate_filter is direct_parent_filter or any(
                child_filter is command_filter
                for child_filter in candidate_filter.sub_command_filters
            ):
                return candidate

        if isinstance(command_filter, CommandFilter):
            raw_parent_names = getattr(command_filter, "parent_command_names", [])
        else:
            raw_parent_names = (
                direct_parent_filter.get_complete_command_names()
                if direct_parent_filter is not None
                else []
            )
        parent_names = {
            str(name).strip() for name in raw_parent_names if str(name).strip()
        }
        if not parent_names:
            return None

        best_match: StarHandlerMetadata | None = None
        best_depth = -1
        for candidate in star_handlers_registry:
            if candidate is handler:
                continue
            if candidate.handler_module_path != handler.handler_module_path:
                continue
            candidate_filter = cls._primary_command_filter(candidate)
            if not isinstance(candidate_filter, CommandGroupFilter):
                continue
            candidate_names = {
                str(name).strip()
                for name in candidate_filter.get_complete_command_names()
                if str(name).strip()
            }
            overlap = parent_names & candidate_names
            if not overlap:
                continue
            depth = max(len(name.split()) for name in overlap)
            if depth > best_depth:
                best_match = candidate
                best_depth = depth
        return best_match

    @staticmethod
    def _has_explicit_permission_config(cmd_cfg: dict[str, Any] | None) -> bool:
        if not isinstance(cmd_cfg, dict):
            return False
        for key in (PERMISSION_CONFIG_KEY, LEGACY_PERMISSION_KEY):
            if key in cmd_cfg:
                value = PermissionManagerCommands.normalize_permission(
                    cmd_cfg.get(key),
                    default="",
                )
                if value in PERMISSION_LEVELS:
                    return True
        return False

    @classmethod
    def _backfill_legacy_permission_fields(
        cls,
        alter_cmd_cfg: dict[str, Any],
    ) -> int:
        """Normalize old records and add a safe core fallback field.

        A valid, already-present ``admin``/``member`` value is deliberately
        preserved even when it conflicts with ``permission_level`` because it
        may be a later change made through AstrBot's native ``/alter_cmd``.
        Records that only contain the legacy field are upgraded to the richer
        ``permission_level`` representation as well.  This keeps a manually
        stored ``group_admin`` value restrictive if the manager is disabled.
        """

        migrated = 0
        for plugin_cfg in alter_cmd_cfg.values():
            if not isinstance(plugin_cfg, dict):
                continue
            for cmd_cfg in plugin_cfg.values():
                if not isinstance(cmd_cfg, dict):
                    continue
                changed = False
                configured = None
                if PERMISSION_CONFIG_KEY in cmd_cfg:
                    candidate = cls.normalize_permission(
                        cmd_cfg.get(PERMISSION_CONFIG_KEY),
                        default="",
                    )
                    if candidate in PERMISSION_LEVELS:
                        configured = candidate

                legacy_value = cmd_cfg.get(LEGACY_PERMISSION_KEY)
                if configured is None and isinstance(legacy_value, str):
                    candidate = cls.normalize_permission(legacy_value, default="")
                    if candidate in PERMISSION_LEVELS:
                        # Preserve the richer legacy spelling as a canonical
                        # field, then replace the core fallback with a value
                        # AstrBot actually understands.
                        configured = candidate
                        if cmd_cfg.get(PERMISSION_CONFIG_KEY) != configured:
                            cmd_cfg[PERMISSION_CONFIG_KEY] = configured
                            changed = True

                if configured is None:
                    continue

                # AstrBot's core compares this field literally (``==
                # "admin"``); normalized spellings such as ``"ADMIN"`` or
                # malformed JSON values therefore are not safe fallbacks.
                # Check the type before set membership so lists/dicts cannot
                # raise ``TypeError`` while being migrated.  A valid literal
                # is preserved because it may be a later native override.
                if isinstance(legacy_value, str) and legacy_value in {
                    "admin",
                    "member",
                }:
                    if changed:
                        migrated += 1
                    continue
                cmd_cfg[LEGACY_PERMISSION_KEY] = (
                    "admin"
                    if configured
                    in {PERMISSION_FRAMEWORK_ADMIN, PERMISSION_GROUP_ADMIN}
                    else "member"
                )
                if cmd_cfg[LEGACY_PERMISSION_KEY] != legacy_value:
                    changed = True
                if changed:
                    migrated += 1
        return migrated

    def _get_command_config(
        self,
        handler: StarHandlerMetadata,
        config: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        config = config if isinstance(config, dict) else self._stored_permission_config
        plugin_cfg = config.get(self._get_plugin_name_for_handler(handler), {})
        if not isinstance(plugin_cfg, dict):
            return {}
        command_cfg = plugin_cfg.get(handler.handler_name, {})
        return command_cfg if isinstance(command_cfg, dict) else {}

    def _explicit_configured_permission(
        self,
        cmd_cfg: dict[str, Any] | None,
    ) -> str | None:
        if not isinstance(cmd_cfg, dict):
            return None

        configured: str | None = None
        if PERMISSION_CONFIG_KEY in cmd_cfg:
            candidate = self.normalize_permission(
                cmd_cfg.get(PERMISSION_CONFIG_KEY),
                default="",
            )
            if candidate in PERMISSION_LEVELS:
                configured = candidate

        if configured is None and LEGACY_PERMISSION_KEY in cmd_cfg:
            candidate = self.normalize_permission(
                cmd_cfg.get(LEGACY_PERMISSION_KEY),
                default="",
            )
            if candidate in PERMISSION_LEVELS:
                return candidate

        if configured is None:
            return None

        # The plugin writes ``permission=admin`` for both of its restrictive
        # levels so old AstrBot versions remain fail-closed.  If the native
        # manager subsequently changed that legacy field, honor the change.
        legacy_value = cmd_cfg.get(LEGACY_PERMISSION_KEY)
        expected_legacy = (
            "admin"
            if configured in {PERMISSION_FRAMEWORK_ADMIN, PERMISSION_GROUP_ADMIN}
            else "member"
        )
        if (
            isinstance(legacy_value, str)
            and legacy_value in {"admin", "member"}
            and legacy_value != expected_legacy
        ):
            return self.normalize_permission(legacy_value)
        return configured

    def _configured_permission(
        self,
        cmd_cfg: dict[str, Any] | None,
        handler: StarHandlerMetadata | None = None,
        _seen: set[str] | None = None,
    ) -> str:
        """Return the canonical level, including group permission inheritance."""

        configured = self._explicit_configured_permission(cmd_cfg)
        if configured is not None:
            # During the first pass AstrBot has already injected its legacy
            # ADMIN/MEMBER filter from this same persisted record.  The
            # plugin's richer permission_level must win that initial pass.
            # Once running, a changed sentinel/native filter is an explicit
            # runtime /alter_cmd override and may be observed.
            if handler is not None and self._permission_config_loaded:
                native_override = self._native_permission_override(handler)
                if native_override is not None:
                    return native_override
            return configured

        if handler is not None:
            # A native filter appearing after this plugin was loaded is an
            # explicit runtime change made by AstrBot's command manager.
            native_override = self._native_permission_override(handler)
            if native_override is not None:
                return native_override

        if handler is not None:
            seen = set(_seen or ())
            seen.add(handler.handler_full_name)
            parent = self._find_parent_group_handler(handler)
            while parent and parent.handler_full_name not in seen:
                seen.add(parent.handler_full_name)
                parent_cfg = self._get_command_config(parent)
                # Only an explicit group setting inherits.  This preserves a
                # child's own native decorator while allowing a Page change
                # on any ancestor group to cover all of its sub-commands.
                if self._has_explicit_permission_config(parent_cfg):
                    return self._configured_permission(parent_cfg, parent, seen)
                parent = self._find_parent_group_handler(parent)

            return self._native_permission_level(handler)
        return PERMISSION_EVERYONE

    def get_effective_permission(self, handler: StarHandlerMetadata) -> str:
        """Get a handler's effective level for the async event gate."""

        cached = self._permission_levels.get(handler.handler_full_name)
        if cached in PERMISSION_LEVELS and not self._permission_config_loaded:
            native_override = self._native_permission_override(handler)
            if native_override is None:
                return cached

        # Do not return a stale cache entry: AstrBot's native ``/alter_cmd``
        # can mutate a live handler without notifying this plugin, and a root
        # group change must immediately affect already-registered children.
        cmd_cfg = self._get_command_config(handler)
        level = self._configured_permission(cmd_cfg, handler)
        self._permission_levels[handler.handler_full_name] = level
        return level

    def is_private_chat_enabled(
        self,
        handler: StarHandlerMetadata,
        _seen: set[str] | None = None,
    ) -> bool:
        """Return the command's effective private-chat availability.

        An explicit command value wins. Command-group children inherit the
        closest configured parent value so the otherwise non-executable group
        row in the Page can control its subcommands.

        Args:
            handler: Command handler whose private-chat policy is requested.
            _seen: Internal recursion guard for malformed group hierarchies.

        Returns:
            True when the command may run in private chat.
        """

        command_cfg = self._get_command_config(handler)
        if PRIVATE_CHAT_CONFIG_KEY in command_cfg:
            configured = ManagedCommandAccessFilter._coerce_bool(
                command_cfg.get(PRIVATE_CHAT_CONFIG_KEY),
            )
            if configured is not None:
                return configured

        seen = set(_seen or ())
        if handler.handler_full_name in seen:
            return True
        seen.add(handler.handler_full_name)
        parent = self._find_parent_group_handler(handler)
        if parent is not None:
            return self.is_private_chat_enabled(parent, seen)
        return True

    def _set_runtime_permission(
        self,
        handler: StarHandlerMetadata,
        permission: str,
    ) -> None:
        """Replace core permission filters with the plugin's async gate.

        This only touches command handlers.  Permission filters on ordinary
        event listeners remain owned by their original plugin.
        """

        if not self._is_command_handler(handler):
            return

        if ORIGINAL_PERMISSION_FILTERS_KEY not in handler.extras_configs:
            handler.extras_configs[ORIGINAL_PERMISSION_FILTERS_KEY] = [
                (index, event_filter)
                for index, event_filter in enumerate(handler.event_filters)
                if isinstance(event_filter, PermissionTypeFilter)
                and not getattr(event_filter, "managed_by_permission_manager", False)
                and not getattr(event_filter, FALLBACK_PERMISSION_FILTER_ATTR, False)
            ]
        handler.event_filters = [
            event_filter
            for event_filter in handler.event_filters
            if not isinstance(event_filter, PermissionTypeFilter)
            and not getattr(event_filter, "managed_by_permission_manager", False)
            and not getattr(event_filter, FALLBACK_PERMISSION_FILTER_ATTR, False)
        ]
        managed_filter = ManagedCommandAccessFilter(
            handler,
            permission,
            self.context,
            self.plugin_config,
            self.group_role_cache,
            permission_resolver=self.get_effective_permission,
            private_chat_resolver=self.is_private_chat_enabled,
            private_chat_enabled=self.is_private_chat_enabled(handler),
        )
        compat_filter = ManagedPermissionCompatFilter(permission)
        # Put the harmless native sentinel first.  AstrBot's /alter_cmd
        # implementation searches for the first PermissionTypeFilter and
        # mutates it in place; keeping the sentinel at index 0 prevents a new
        # legacy filter from being inserted ahead of the richer access gate.
        # The managed filter still checks the message prefix itself, so
        # non-command events pass through.
        handler.event_filters.insert(0, compat_filter)
        handler.event_filters.insert(1, managed_filter)
        self._permission_levels[handler.handler_full_name] = permission

    def _refresh_runtime_permissions(self) -> None:
        """Re-evaluate every command after a configuration change.

        Group permissions are inherited by child handlers.  Refreshing the
        whole registry keeps an already-running child from retaining a stale
        restrictive filter after its parent is opened in the Page.
        """

        # A refresh is a configuration application pass.  Keep the loaded
        # marker cleared while resolving levels so an existing compatibility
        # sentinel (or a native filter injected by AstrBot during startup)
        # cannot override the explicit ``permission_level`` from the page.
        # Restore the active state only after every handler has been rebuilt;
        # subsequent event checks may then observe a genuine /alter_cmd change.
        was_loaded = self._permission_config_loaded
        self._permission_config_loaded = False
        try:
            self._permission_levels.clear()
            for handler in star_handlers_registry:
                if not isinstance(handler, StarHandlerMetadata):
                    continue
                if not self._is_command_handler(handler):
                    continue
                command_cfg = self._get_command_config(handler)
                permission = self._configured_permission(command_cfg, handler)
                self._set_runtime_permission(handler, permission)
        except Exception:
            self._permission_config_loaded = was_loaded
            raise
        else:
            self._permission_config_loaded = True

    def _has_group_permission_override(
        self,
        handler: StarHandlerMetadata,
        _seen: set[str] | None = None,
    ) -> bool:
        """Return whether a handler or one of its parent groups is configured."""

        if self._has_explicit_permission_config(self._get_command_config(handler)):
            return True
        seen = set(_seen or ())
        if handler.handler_full_name in seen:
            return False
        seen.add(handler.handler_full_name)
        parent = self._find_parent_group_handler(handler)
        return bool(parent and self._has_group_permission_override(parent, seen))

    async def restore_runtime_permissions(self) -> None:
        """Restore or rebuild filters when the plugin is unloaded.

        Explicit persisted permissions remain enforced by a plain AstrBot
        compatibility filter after this plugin is gone.  Commands without an
        explicit override regain the filters they had before this plugin took
        control.
        """

        alter_cmd_cfg = await sp.global_get("alter_cmd", {})
        if not isinstance(alter_cmd_cfg, dict):
            alter_cmd_cfg = {}
        self._stored_permission_config = alter_cmd_cfg

        for handler in star_handlers_registry:
            if not isinstance(handler, StarHandlerMetadata):
                continue
            original_filters = handler.extras_configs.get(
                ORIGINAL_PERMISSION_FILTERS_KEY,
            )
            if not isinstance(original_filters, list):
                continue

            handler.event_filters = [
                event_filter
                for event_filter in handler.event_filters
                if not isinstance(event_filter, PermissionTypeFilter)
                and not getattr(event_filter, "managed_by_permission_manager", False)
            ]

            cmd_cfg = self._get_command_config(handler, alter_cmd_cfg)
            configured = self._configured_permission(cmd_cfg, handler)
            has_explicit_permission = self._has_group_permission_override(handler)
            if has_explicit_permission:
                # Keep the persistent override fail-closed while the manager
                # is unloaded. group_admin intentionally degrades to ADMIN.
                fallback_filter = PermissionTypeFilter(
                    PermissionType.ADMIN
                    if configured
                    in {
                        PERMISSION_FRAMEWORK_ADMIN,
                        PERMISSION_GROUP_ADMIN,
                    }
                    else PermissionType.MEMBER,
                )
                setattr(fallback_filter, FALLBACK_PERMISSION_FILTER_ATTR, True)
                command_index = next(
                    (
                        index
                        for index, event_filter in enumerate(handler.event_filters)
                        if isinstance(event_filter, (CommandFilter, CommandGroupFilter))
                    ),
                    len(handler.event_filters),
                )
                handler.event_filters.insert(command_index, fallback_filter)
                continue

            for index, event_filter in sorted(
                original_filters,
                key=lambda item: item[0],
            ):
                handler.event_filters.insert(
                    min(max(int(index), 0), len(handler.event_filters)),
                    event_filter,
                )
            handler.extras_configs.pop(ORIGINAL_PERMISSION_FILTERS_KEY, None)

        self._permission_levels.clear()
        self._permission_config_loaded = False

    async def load_permission_state(self) -> None:
        """Load persisted levels and make them active for current handlers."""

        alter_cmd_cfg = await sp.global_get("alter_cmd", {})
        if not isinstance(alter_cmd_cfg, dict):
            alter_cmd_cfg = {}
        migrated = self._backfill_legacy_permission_fields(alter_cmd_cfg)
        if migrated:
            await sp.global_put("alter_cmd", alter_cmd_cfg)
            logger.info(
                f"[PermissionManager] 已补全 {migrated} 条旧版权限回退字段。",
            )
        self._stored_permission_config = alter_cmd_cfg
        was_loaded = self._permission_config_loaded
        self._permission_config_loaded = False
        try:
            self._permission_levels.clear()

            for handler in star_handlers_registry:
                if not isinstance(
                    handler, StarHandlerMetadata
                ) or not self._is_command_handler(handler):
                    continue
                plugin_name = self._get_plugin_name_for_handler(handler)
                plugin_cfg = alter_cmd_cfg.get(plugin_name, {})
                cmd_cfg = (
                    plugin_cfg.get(handler.handler_name, {})
                    if isinstance(plugin_cfg, dict)
                    else {}
                )
                level = self._configured_permission(cmd_cfg, handler)
                self._set_runtime_permission(handler, level)
        except Exception:
            self._permission_config_loaded = was_loaded
            raise
        else:
            self._permission_config_loaded = True

    def _get_logo_data_url(self, logo_path: str) -> str | None:
        """Return a small, reusable data URL for a plugin logo.

        The dashboard file-token endpoint intentionally consumes tokens after
        one request. A data URL keeps the Page logo usable when its table is
        redrawn or when the detail view is opened after the list view.
        """
        try:
            stat_result = os.stat(logo_path)
        except OSError:
            return None

        signature = (stat_result.st_mtime_ns, stat_result.st_size)
        cached = self._logo_data_cache.get(logo_path)
        if cached and cached[:2] == signature:
            return cached[2]

        mime_type = "image/png"
        try:
            # AstrBot already ships Pillow, but keep a raw-file fallback so a
            # minimal installation can still display the logo.
            from PIL import Image

            resampling = getattr(Image, "Resampling", Image)
            with Image.open(logo_path) as image:
                image.thumbnail((96, 96), resampling.LANCZOS)
                if image.mode not in ("RGB", "RGBA"):
                    image = image.convert("RGBA")
                buffer = BytesIO()
                image.save(buffer, format="WEBP", quality=82, method=4)
                payload = buffer.getvalue()
            mime_type = "image/webp"
        except Exception as exc:
            logger.debug(f"无法压缩插件 Logo，使用原始文件: {logo_path}: {exc}")
            try:
                with open(logo_path, "rb") as logo_file:
                    payload = logo_file.read()
                mime_type = mimetypes.guess_type(logo_path)[0] or mime_type
            except OSError:
                return None

        data_url = (
            f"data:{mime_type};base64,{base64.b64encode(payload).decode('ascii')}"
        )
        self._logo_data_cache[logo_path] = (*signature, data_url)
        return data_url

    def _get_plugin_metadata(self, plugin_name: str) -> dict[str, Any]:
        if plugin_name == "builtin_commands":
            return {
                "display_name": "系统内置指令",
                "desc": "AstrBot 核心自带的系统内置管理和功能指令",
                "author": "AstrBot",
                "version": "内置",
                "has_logo": False,
                "logo_path": None,
            }
        for plugin in star_map.values():
            if plugin.name == plugin_name:
                return {
                    "display_name": plugin.display_name or plugin.name,
                    "desc": plugin.desc or plugin.short_desc or "暂无简介",
                    "author": plugin.author or "未知",
                    "version": plugin.version or "1.0.0",
                    "has_logo": bool(
                        plugin.logo_path and os.path.exists(plugin.logo_path)
                    ),
                    "logo_path": plugin.logo_path
                    if plugin.logo_path and os.path.exists(plugin.logo_path)
                    else None,
                }
        return {
            "display_name": plugin_name,
            "desc": "暂无简介",
            "author": "未知",
            "version": "1.0.0",
            "has_logo": False,
            "logo_path": None,
        }

    def _get_all_commands_by_plugin(self) -> dict[str, list[tuple]]:
        plugin_commands = {}
        for handler in star_handlers_registry:
            assert isinstance(handler, StarHandlerMetadata)

            # 判断内置命令或外部插件
            plugin_name = None
            if handler.handler_module_path in star_map:
                plugin = star_map[handler.handler_module_path]
                if not plugin.activated:
                    continue
                plugin_name = plugin.name
            elif "builtin" in handler.handler_module_path:
                plugin_name = "builtin_commands"
            else:
                parts = handler.handler_module_path.split(".")
                if len(parts) >= 3 and parts[0] == "data" and parts[1] == "plugins":
                    plugin_name = parts[2]
                else:
                    plugin_name = "builtin_commands"

            if plugin_name not in plugin_commands:
                plugin_commands[plugin_name] = []

            for event_filter in handler.event_filters:
                if isinstance(event_filter, CommandFilter):
                    plugin_commands[plugin_name].append(
                        (handler, event_filter.command_name, "command", False)
                    )
                    break
                elif isinstance(event_filter, CommandGroupFilter):
                    plugin_commands[plugin_name].append(
                        (handler, event_filter.group_name, "command_group", True)
                    )
                    break
        return plugin_commands

    async def get_all_plugins_api(self):
        plugin_commands = self._get_all_commands_by_plugin()
        plugins = []
        for name, cmds in plugin_commands.items():
            meta = self._get_plugin_metadata(name)
            plugins.append(
                {
                    "name": name,
                    "display_name": meta["display_name"],
                    "desc": meta["desc"],
                    "author": meta["author"],
                    "version": meta["version"],
                    "has_logo": meta["has_logo"],
                    "logo": self._get_logo_data_url(meta["logo_path"])
                    if meta["logo_path"]
                    else None,
                    "command_count": len([c for c in cmds if c[2] == "command"]),
                    "group_count": len([c for c in cmds if c[3]]),
                    "total_commands": len(cmds),
                }
            )
        plugins.sort(key=lambda x: x["display_name"].lower())
        return plugins

    async def get_plugin_commands_api(self, plugin_name: str):
        plugin_commands = self._get_all_commands_by_plugin()
        if plugin_name not in plugin_commands:
            return None
        cmds = plugin_commands[plugin_name]
        alter_cmd_cfg = await sp.global_get("alter_cmd", {})
        if not isinstance(alter_cmd_cfg, dict):
            alter_cmd_cfg = {}
        self._stored_permission_config = alter_cmd_cfg
        plugin_cfg = alter_cmd_cfg.get(plugin_name, {})
        if not isinstance(plugin_cfg, dict):
            plugin_cfg = {}

        command_list = []
        group_list = []
        for handler, cmd_name, cmd_type, is_group in cmds:
            cmd_cfg = plugin_cfg.get(handler.handler_name, {})
            current_perm = self._configured_permission(cmd_cfg, handler)

            aliases = self._resolve_command_aliases(cmd_cfg, handler)

            info = {
                "name": cmd_cfg.get("name", cmd_name),
                "original_name": cmd_name,
                "handler": handler.handler_name,
                "permission": current_perm,
                "private_chat_enabled": self.is_private_chat_enabled(handler),
                "aliases": aliases,
                "desc": handler.desc or "",
            }
            if is_group:
                group_list.append(info)
            else:
                command_list.append(info)

        command_list.sort(key=lambda x: x["name"].lower())
        group_list.sort(key=lambda x: x["name"].lower())
        return {"commands": command_list, "groups": group_list}

    async def get_all_commands_api(self):
        plugin_commands = self._get_all_commands_by_plugin()
        alter_cmd_cfg = await sp.global_get("alter_cmd", {})
        if not isinstance(alter_cmd_cfg, dict):
            alter_cmd_cfg = {}
        self._stored_permission_config = alter_cmd_cfg

        all_cmds = []
        for plugin_name, cmds in plugin_commands.items():
            plugin_cfg = alter_cmd_cfg.get(plugin_name, {})
            if not isinstance(plugin_cfg, dict):
                plugin_cfg = {}
            meta = self._get_plugin_metadata(plugin_name)

            for handler, cmd_name, cmd_type, is_group in cmds:
                cmd_cfg = plugin_cfg.get(handler.handler_name, {})
                current_perm = self._configured_permission(cmd_cfg, handler)

                aliases = self._resolve_command_aliases(cmd_cfg, handler)

                all_cmds.append(
                    {
                        "plugin_name": plugin_name,
                        "plugin_display_name": meta["display_name"],
                        "name": cmd_cfg.get("name", cmd_name),
                        "original_name": cmd_name,
                        "handler": handler.handler_name,
                        "permission": current_perm,
                        "private_chat_enabled": self.is_private_chat_enabled(
                            handler,
                        ),
                        "aliases": aliases,
                        "desc": handler.desc or "",
                        "is_group": is_group,
                    }
                )
        all_cmds.sort(key=lambda x: x["name"].lower())
        return all_cmds

    def _get_plugin_name_for_handler(self, handler: StarHandlerMetadata) -> str:
        if handler.handler_module_path in star_map:
            return star_map[handler.handler_module_path].name
        if "builtin" in handler.handler_module_path:
            return "builtin_commands"
        parts = handler.handler_module_path.split(".")
        if len(parts) >= 3 and parts[0] == "data" and parts[1] == "plugins":
            return parts[2]
        return "builtin_commands"

    def _find_handler(
        self, plugin_name: str, handler_name: str
    ) -> StarHandlerMetadata | None:
        for handler in star_handlers_registry:
            if (
                handler.handler_name == handler_name
                and self._get_plugin_name_for_handler(handler) == plugin_name
            ):
                return handler
        return None

    def _get_handler_aliases(self, handler: StarHandlerMetadata) -> list[str]:
        for f in handler.event_filters:
            if isinstance(f, (CommandFilter, CommandGroupFilter)) and f.alias:
                return list(f.alias)
        return []

    def _resolve_command_aliases(
        self, cmd_cfg: dict[str, Any], handler: StarHandlerMetadata
    ) -> list[str]:
        if "aliases" in cmd_cfg:
            aliases = cmd_cfg.get("aliases", [])
            return (
                aliases
                if isinstance(aliases, list)
                else list(aliases)
                if aliases
                else []
            )
        return self._get_handler_aliases(handler)

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

    def _apply_command_identity(
        self,
        handler: StarHandlerMetadata,
        name: str | None = None,
        aliases: list[str] | None = None,
    ) -> bool:
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
        normalized = self.normalize_permission(permission, default="")
        if normalized not in PERMISSION_LEVELS:
            raise ValueError("无效的权限等级")

        handler = self._find_handler(plugin_name, handler_name)
        if handler is None or not self._is_command_handler(handler):
            raise ValueError("未找到指定的命令处理器")

        alter_cmd_cfg = await sp.global_get("alter_cmd", {})
        if not isinstance(alter_cmd_cfg, dict):
            alter_cmd_cfg = {}
        plugin_cfg = alter_cmd_cfg.setdefault(plugin_name, {})
        cmd_cfg = plugin_cfg.setdefault(handler_name, {})
        cmd_cfg[PERMISSION_CONFIG_KEY] = normalized
        # AstrBot core still reads this legacy field during plugin loading.
        # Keep group_admin restrictive as well: if this plugin is disabled or
        # still starting, it safely degrades to framework-admin-only rather
        # than opening a protected command to everyone.
        cmd_cfg[LEGACY_PERMISSION_KEY] = (
            "admin"
            if normalized
            in {
                PERMISSION_FRAMEWORK_ADMIN,
                PERMISSION_GROUP_ADMIN,
            }
            else "member"
        )
        await sp.global_put("alter_cmd", alter_cmd_cfg)

        self._stored_permission_config = alter_cmd_cfg
        self._refresh_runtime_permissions()
        return True

    async def set_command_private_chat(
        self,
        plugin_name: str,
        handler_name: str,
        enabled: bool,
    ) -> bool:
        """Set one command's private-chat availability.

        Args:
            plugin_name: Plugin owning the command handler.
            handler_name: AstrBot handler name.
            enabled: Whether the command may execute in private chat.

        Returns:
            True after the setting has been persisted.

        Raises:
            ValueError: If the handler does not exist or enabled is not bool.
        """

        if not isinstance(enabled, bool):
            raise ValueError("私聊开关必须是布尔值")

        handler = self._find_handler(plugin_name, handler_name)
        if handler is None or not self._is_command_handler(handler):
            raise ValueError("未找到指定的命令处理器")

        alter_cmd_cfg = await sp.global_get("alter_cmd", {})
        if not isinstance(alter_cmd_cfg, dict):
            alter_cmd_cfg = {}
        plugin_cfg = alter_cmd_cfg.setdefault(plugin_name, {})
        if not isinstance(plugin_cfg, dict):
            plugin_cfg = {}
            alter_cmd_cfg[plugin_name] = plugin_cfg
        cmd_cfg = plugin_cfg.setdefault(handler_name, {})
        if not isinstance(cmd_cfg, dict):
            cmd_cfg = {}
            plugin_cfg[handler_name] = cmd_cfg
        cmd_cfg[PRIVATE_CHAT_CONFIG_KEY] = enabled
        await sp.global_put("alter_cmd", alter_cmd_cfg)

        self._stored_permission_config = alter_cmd_cfg
        return True

    async def apply_all_permissions(self):
        alter_cmd_cfg = await sp.global_get("alter_cmd", {})
        if not isinstance(alter_cmd_cfg, dict):
            alter_cmd_cfg = {}
        migrated = self._backfill_legacy_permission_fields(alter_cmd_cfg)
        if migrated:
            await sp.global_put("alter_cmd", alter_cmd_cfg)
            logger.info(
                f"[PermissionManager] 已补全 {migrated} 条旧版权限回退字段。",
            )

        self._stored_permission_config = alter_cmd_cfg
        was_loaded = self._permission_config_loaded
        self._permission_config_loaded = False
        try:
            self._permission_levels.clear()

            logger.info("[PermissionManager] 正在应用指令身份与三级权限配置...")
            applied_count = 0

            for handler in star_handlers_registry:
                assert isinstance(handler, StarHandlerMetadata)
                if not self._is_command_handler(handler):
                    continue

                plugin_name = self._get_plugin_name_for_handler(handler)

                if not plugin_name:
                    continue

                plugin_cfg = alter_cmd_cfg.get(plugin_name, {})
                cmd_cfg = (
                    plugin_cfg.get(handler.handler_name, {})
                    if isinstance(plugin_cfg, dict)
                    else {}
                )
                name = cmd_cfg.get("name")
                aliases = cmd_cfg.get("aliases") if "aliases" in cmd_cfg else None

                if name is not None or aliases is not None:
                    if self._apply_command_identity(
                        handler, name=name, aliases=aliases
                    ):
                        applied_count += 1

                permission = self._configured_permission(cmd_cfg, handler)
                self._set_runtime_permission(handler, permission)
                applied_count += 1

            logger.info(
                f"[PermissionManager] 已应用 {applied_count} 个指令的身份与权限配置。",
            )
        except Exception:
            self._permission_config_loaded = was_loaded
            raise
        else:
            # ``apply_all_permissions`` is also called when another plugin is
            # loaded.  Marking the pass as loaded only after all handlers have
            # been rebuilt prevents the legacy native filter on a late-loaded
            # handler from turning an explicit group_admin setting into
            # framework_admin.
            self._permission_config_loaded = True

    async def get_all_tools_api(self):
        llm_tools = self.context.provider_manager.llm_tools

        # 内置工具
        builtin_tools = llm_tools.iter_builtin_tools()
        # 其他插件/MCP工具
        other_tools = llm_tools.func_list

        all_tools = []

        # 1. 内置工具
        for t in builtin_tools:
            all_tools.append(
                {
                    "name": t.name,
                    "desc": t.description or "无描述",
                    "active": getattr(t, "active", True),
                    "type": "builtin",
                }
            )

        # 2. 其他工具
        for t in other_tools:
            t_type = "plugin"
            if hasattr(t, "mcp_server_name") or "mcp" in str(type(t)).lower():
                t_type = "mcp"
            all_tools.append(
                {
                    "name": t.name,
                    "desc": t.description or "无描述",
                    "active": getattr(t, "active", True),
                    "type": t_type,
                }
            )

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

        return sorted(dedup.values(), key=lambda x: x["name"].lower())

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
        self.config = config or {}
        self._group_role_cache: dict[
            str,
            tuple[float, str | None, set[str]],
        ] = {}
        self.perm_logic = PermissionManagerCommands(
            context,
            self.config,
            self._group_role_cache,
        )
        self._cooldown_next_available: dict[str, float] = {}
        self._cooldown_locks: dict[str, asyncio.Lock] = {}
        self._delayed_permission_task: asyncio.Task | None = None

        # 注册 Native Pages API
        context.register_web_api(
            f"/{PLUGIN_NAME}/plugins", self.api_list_plugins, ["GET"], "获取插件列表"
        )
        context.register_web_api(
            f"/{PLUGIN_NAME}/plugin/<plugin_name>/commands",
            self.api_plugin_commands,
            ["GET"],
            "获取命令列表",
        )
        context.register_web_api(
            f"/{PLUGIN_NAME}/command/<plugin_name>/<handler_name>/set-permission",
            self.api_set_perm,
            ["POST"],
            "设置权限",
        )
        context.register_web_api(
            f"/{PLUGIN_NAME}/command/<plugin_name>/<handler_name>/set-private-chat",
            self.api_set_private_chat,
            ["POST"],
            "设置指令私聊可用性",
        )
        context.register_web_api(
            f"/{PLUGIN_NAME}/plugin/<plugin_name>/set-permission",
            self.api_batch_perm,
            ["POST"],
            "批量设置权限",
        )
        context.register_web_api(
            f"/{PLUGIN_NAME}/command/<plugin_name>/<handler_name>/set-name",
            self.api_set_name,
            ["POST"],
            "修改名称",
        )
        context.register_web_api(
            f"/{PLUGIN_NAME}/command/<plugin_name>/<handler_name>/set-aliases",
            self.api_set_aliases,
            ["POST"],
            "设置别名",
        )

        # 新增 API
        context.register_web_api(
            f"/{PLUGIN_NAME}/commands/all",
            self.api_all_commands,
            ["GET"],
            "获取所有命令列表",
        )
        context.register_web_api(
            f"/{PLUGIN_NAME}/plugin/<plugin_name>/logo",
            self.api_plugin_logo,
            ["GET"],
            "获取插件Logo",
        )
        context.register_web_api(
            f"/{PLUGIN_NAME}/tools/all",
            self.api_all_tools,
            ["GET"],
            "获取所有函数工具列表",
        )
        context.register_web_api(
            f"/{PLUGIN_NAME}/tools/<name>/set-active",
            self.api_set_tool_active,
            ["POST"],
            "设置函数工具激活状态",
        )

    async def initialize(self):
        """Apply permissions after AstrBot injects its legacy filters."""

        try:
            await self.perm_logic.apply_all_permissions()
        except Exception as exc:
            logger.error(f"[PermissionManager] 初始化权限配置失败: {exc}")

        # On a full AstrBot startup, plugins registered after this one need a
        # second pass. A permission-manager-only reload is already covered by
        # the immediate pass above.
        self._delayed_permission_task = asyncio.create_task(
            self.auto_apply_permissions(),
        )

    async def terminate(self):
        if self._delayed_permission_task is not None:
            self._delayed_permission_task.cancel()
            try:
                await self._delayed_permission_task
            except asyncio.CancelledError:
                pass
            self._delayed_permission_task = None
        await self.perm_logic.restore_runtime_permissions()

    def _get_bool_config(self, key: str, default: bool) -> bool:
        value = self.config.get(key, default)
        if isinstance(value, bool):
            return value
        if isinstance(value, (int, float)):
            return value != 0
        if isinstance(value, str):
            normalized = value.strip().lower()
            if normalized in {"1", "true", "yes", "on", "开启", "是"}:
                return True
            if normalized in {"0", "false", "no", "off", "关闭", "否"}:
                return False
        return default

    def _get_text_config(self, key: str, default: str) -> str:
        """Read an editable text value from plugin configuration.

        Args:
            key: Configuration key.
            default: Value used when the key is absent or unreadable.

        Returns:
            The configured string. An explicitly empty string remains empty.
        """

        try:
            value = self.config.get(key, default)
        except Exception:
            return default
        if value is None:
            return default
        return str(value).strip()

    def _private_chat_enabled(self, handler: StarHandlerMetadata) -> bool:
        return self.perm_logic.is_private_chat_enabled(handler)

    def _private_chat_notify_enabled(self) -> bool:
        return self._get_bool_config("private_chat_notify", False)

    def _private_chat_denied_message(self) -> str:
        return self._get_text_config(
            "private_chat_denied_message",
            DEFAULT_PRIVATE_CHAT_DENIED_MESSAGE,
        )

    def _group_admin_notify_enabled(self) -> bool:
        return self._get_bool_config("group_admin_notify", False)

    def _group_admin_denied_message(self) -> str:
        return self._get_text_config(
            "group_admin_denied_message",
            DEFAULT_GROUP_ADMIN_DENIED_MESSAGE,
        )

    def _is_framework_admin(self, event: AstrMessageEvent) -> bool:
        """Check AstrBot's framework administrator list."""

        if event.is_admin():
            return True

        try:
            astrbot_config = self.context.get_config()
            raw_admin_ids = astrbot_config.get("admins_id", [])
        except Exception as exc:
            logger.debug(f"[PermissionManager] 读取 admins_id 失败: {exc}")
            raw_admin_ids = []

        if isinstance(raw_admin_ids, (str, int)):
            raw_admin_ids = [raw_admin_ids]
        if not isinstance(raw_admin_ids, (list, tuple, set)):
            raw_admin_ids = []

        sender_id = str(event.get_sender_id() or "").strip()
        return bool(sender_id) and sender_id in {
            str(admin_id).strip() for admin_id in raw_admin_ids if str(admin_id).strip()
        }

    @staticmethod
    def _get_object_value(obj: Any, key: str, default: Any = None) -> Any:
        if obj is None:
            return default
        if isinstance(obj, dict):
            return obj.get(key, default)
        getter = getattr(obj, "get", None)
        if callable(getter):
            try:
                value = getter(key, default)
                if value is not None:
                    return value
            except Exception:
                pass
        return getattr(obj, key, default)

    @classmethod
    def _normalize_group_role(cls, role: Any) -> str | None:
        if role is None:
            return None
        value = str(role).strip().lower()
        if value in {
            "owner",
            "creator",
            "group_owner",
            "group-owner",
            "群主",
        }:
            return "owner"
        if value in {
            "admin",
            "administrator",
            "group_admin",
            "group-admin",
            "moderator",
            "群管理员",
            "管理员",
        }:
            return "admin"
        if value in {"member", "normal", "user", "普通成员", "成员"}:
            return "member"
        return None

    @classmethod
    def _extract_raw_group_role(cls, event: AstrMessageEvent) -> str | None:
        raw_message = getattr(event.message_obj, "raw_message", None)
        candidates = []
        for key in ("sender", "author", "member", "user"):
            candidate = cls._get_object_value(raw_message, key)
            if candidate is not None:
                candidates.append(candidate)
        # A few adapters normalize the sender onto AstrBotMessage while
        # retaining no role in ``raw_message``.
        normalized_sender = getattr(event.message_obj, "sender", None)
        if normalized_sender is not None:
            candidates.append(normalized_sender)

        for candidate in candidates:
            for key in ("role", "member_role", "group_role"):
                normalized = cls._normalize_group_role(
                    cls._get_object_value(candidate, key),
                )
                if normalized:
                    return normalized
        return None

    @classmethod
    def _normalize_member_ids(cls, values: Any) -> set[str]:
        if values is None:
            return set()
        if isinstance(values, (str, int)):
            values = [values]
        if not isinstance(values, (list, tuple, set)):
            values = [values]

        result: set[str] = set()
        for value in values:
            member_id = value
            if not isinstance(value, (str, int)):
                member_id = None
                for key in ("user_id", "id", "openid", "member_openid"):
                    member_id = cls._get_object_value(value, key)
                    if member_id is not None:
                        break
            normalized = str(member_id or "").strip()
            if normalized:
                result.add(normalized)
        return result

    @classmethod
    def _group_identity(cls, group: Any) -> tuple[str | None, set[str]]:
        owner = cls._get_object_value(group, "group_owner")
        if owner is None:
            owner = cls._get_object_value(group, "owner")
        owner_ids = cls._normalize_member_ids(owner)
        owner_id = next(iter(owner_ids), None)

        admins = cls._get_object_value(group, "group_admins")
        if admins is None:
            admins = cls._get_object_value(group, "admins")
        return owner_id, cls._normalize_member_ids(admins)

    async def _is_group_owner_or_admin(self, event: AstrMessageEvent) -> bool:
        """Resolve a sender's group role, using an adapter API when needed."""

        if event.is_private_chat() or not event.get_group_id():
            return False

        raw_role = self._extract_raw_group_role(event)
        # Treat an explicit normal-member role as a fail-closed answer before
        # consulting potentially stale group metadata or the role cache.
        if raw_role == "member":
            return False
        if raw_role in {"owner", "admin"}:
            return True

        sender_id = str(event.get_sender_id() or "").strip()
        current_group = getattr(event.message_obj, "group", None)
        owner_id, admin_ids = self._group_identity(current_group)
        # Keep the owner fast path, but fail closed on an explicit member role
        # before trusting a contradictory administrator list.
        if sender_id and sender_id == owner_id:
            return True
        if sender_id and sender_id in admin_ids:
            return True
        # An empty list on the message object is frequently only a placeholder;
        # let the adapter API resolve it.  A populated list can be treated as a
        # complete negative result and avoids an unnecessary network lookup.
        if admin_ids:
            return False

        cache_key = self._get_cooldown_scope(event)
        now = time.monotonic()
        cached = self._group_role_cache.get(cache_key)
        if cached and cached[0] > now:
            _, cached_owner, cached_admins = cached
            return bool(
                sender_id and (sender_id == cached_owner or sender_id in cached_admins)
            )

        try:
            group = await asyncio.wait_for(event.get_group(), timeout=3.0)
            owner_id, admin_ids = self._group_identity(group)
        except (AttributeError, NotImplementedError, asyncio.TimeoutError) as exc:
            logger.debug(
                f"[PermissionManager] 当前适配器无法查询群管理员信息: {exc}",
            )
            owner_id, admin_ids = None, set()
        except Exception as exc:
            logger.debug(f"[PermissionManager] 查询群管理员信息失败: {exc}")
            owner_id, admin_ids = None, set()

        self._group_role_cache[cache_key] = (
            now + GROUP_ROLE_CACHE_TTL,
            owner_id,
            admin_ids,
        )
        return bool(sender_id and (sender_id == owner_id or sender_id in admin_ids))

    def _reparse_command_handler(
        self,
        event: AstrMessageEvent,
        handler: StarHandlerMetadata,
    ) -> dict[str, Any] | None:
        """Parse parameters for a handler released by the async role lookup."""

        try:
            cfg = self.context.get_config()
        except Exception:
            cfg = {}
        event._extras.pop("parsed_params", None)
        found_command_filter = False
        for event_filter in handler.event_filters:
            if isinstance(event_filter, ManagedCommandAccessFilter):
                continue
            if isinstance(event_filter, PermissionTypeFilter):
                continue
            try:
                if isinstance(event_filter, CommandFilter) and not hasattr(
                    event_filter,
                    "handler_params",
                ):
                    # A few third-party plugins construct CommandFilter
                    # instances manually and leave their parameter metadata
                    # uninitialized.  Rebuild it before replaying the filter
                    # for an asynchronously resolved group administrator.
                    event_filter.init_handler_md(handler)
                if not event_filter.filter(event, cfg):
                    return None
                if isinstance(event_filter, CommandFilter):
                    found_command_filter = True
            except Exception as exc:
                logger.debug(
                    f"[PermissionManager] 异步放行命令参数解析失败: {exc}",
                )
                return None
        if not found_command_filter:
            return None
        params = event.get_extra("parsed_params", {})
        return dict(params) if isinstance(params, dict) else {}

    def _prune_shadowed_group_handlers(
        self,
        activated_handlers: list[StarHandlerMetadata],
        blocked: dict[str, dict[str, Any]],
    ) -> None:
        """Remove parent command-group wrappers shadowed by a deeper match.

        AstrBot can activate a CommandGroupFilter handler together with the
        nested group or leaf CommandFilter that actually owns the incoming
        command. Group configuration is already inherited by descendants, so
        retaining the wrapper in the final access decision can let an allowed
        parent mask a denied child or emit the parent's misleading denial
        notice. Only the most specific matching handlers should remain.

        Args:
            activated_handlers: Handlers accepted by the waking stage.
            blocked: Provisional command denials keyed by handler full name.
        """

        present: dict[str, StarHandlerMetadata] = {
            handler.handler_full_name: handler
            for handler in activated_handlers
            if isinstance(handler, StarHandlerMetadata)
            and self._is_command_handler(handler)
        }
        for entry in blocked.values():
            handler = entry.get("handler") if isinstance(entry, dict) else None
            if isinstance(handler, StarHandlerMetadata) and self._is_command_handler(
                handler,
            ):
                present[handler.handler_full_name] = handler

        shadowed: set[str] = set()
        for handler in present.values():
            seen = {handler.handler_full_name}
            parent = self.perm_logic._find_parent_group_handler(handler)
            while parent is not None and parent.handler_full_name not in seen:
                seen.add(parent.handler_full_name)
                if parent.handler_full_name in present:
                    shadowed.add(parent.handler_full_name)
                parent = self.perm_logic._find_parent_group_handler(parent)

        if not shadowed:
            return

        activated_handlers[:] = [
            handler
            for handler in activated_handlers
            if handler.handler_full_name not in shadowed
        ]
        for name, entry in list(blocked.items()):
            handler = entry.get("handler") if isinstance(entry, dict) else None
            if (
                name in shadowed
                or isinstance(handler, StarHandlerMetadata)
                and handler.handler_full_name in shadowed
            ):
                blocked.pop(name, None)

    async def _mark_unactivated_denied_commands(
        self,
        event: AstrMessageEvent,
        activated_handlers: list[StarHandlerMetadata],
        blocked: dict[str, dict[str, Any]],
    ) -> None:
        """Catch a native permission filter that skipped a handler early.

        WakingStage omits a handler whose native ``PermissionTypeFilter``
        rejects the event.  When AstrBot's ``/alter_cmd`` adds such a filter
        after this plugin has loaded, there is no activated handler for the
        central gate to inspect and the event could otherwise fall through to
        the default LLM.  Scan only command-shaped handlers and record denied
        ones; allowed handlers are intentionally left to WakingStage's normal
        parsing path.
        """

        known_names = {handler.handler_full_name for handler in activated_handlers}
        known_names.update(name for name in blocked if isinstance(name, str))
        try:
            core_config = self.context.get_config()
        except Exception:
            core_config = {}
        disable_builtin_commands = bool(
            core_config.get("disable_builtin_commands", False),
        )
        candidates: list[StarHandlerMetadata] = []
        for handler in star_handlers_registry:
            if not isinstance(handler, StarHandlerMetadata):
                continue
            if not handler.enabled:
                continue
            if (
                disable_builtin_commands
                and handler.handler_module_path
                == "astrbot.builtin_stars.builtin_commands.main"
            ):
                continue
            if handler.handler_full_name in known_names:
                continue
            if not self._is_command_handler(handler):
                continue
            plugin = star_map.get(handler.handler_module_path)
            if plugin is None and "builtin" not in handler.handler_module_path:
                continue
            if plugin is not None and not plugin.activated:
                continue
            if not ManagedCommandAccessFilter._handler_matches_command(
                handler,
                event,
            ):
                continue
            plugin_names = getattr(event, "plugins_name", None)
            if plugin_names is not None:
                plugin_name = self.perm_logic._get_plugin_name_for_handler(handler)
                if plugin_name not in plugin_names:
                    continue
            candidates.append(handler)

        if not candidates:
            return

        try:
            candidates = await SessionPluginManager.filter_handlers_by_session(
                event,
                candidates,
            )
        except Exception as exc:
            # A session lookup failure must not open a protected command.
            logger.debug(f"[PermissionManager] 会话指令过滤失败，按安全策略拒绝: {exc}")
            for handler in candidates:
                blocked.setdefault(
                    handler.handler_full_name,
                    {
                        "handler": handler,
                        "parsed_params": {},
                        "reason": "permission",
                    },
                )
            return

        framework_admin = self._is_framework_admin(event)
        group_admin: bool | None = None
        handlers_parsed_params = event.get_extra("handlers_parsed_params", {})
        if not isinstance(handlers_parsed_params, dict):
            handlers_parsed_params = {}
            event.set_extra("handlers_parsed_params", handlers_parsed_params)

        def readd_if_parseable(handler: StarHandlerMetadata) -> bool:
            """Replay a command omitted by a stale native permission filter."""

            reparsed = self._reparse_command_handler(event, handler)
            if reparsed is None:
                return False
            if all(
                existing.handler_full_name != handler.handler_full_name
                for existing in activated_handlers
            ):
                activated_handlers.append(handler)
            handlers_parsed_params[handler.handler_full_name] = reparsed
            return True

        def block_reparse_failure(handler: StarHandlerMetadata) -> None:
            """Keep a recognized command from falling through to the LLM."""

            blocked.setdefault(
                handler.handler_full_name,
                {
                    "handler": handler,
                    "parsed_params": {},
                    "reason": "command_reparse_failed",
                },
            )

        for handler in candidates:
            permission = self.perm_logic.get_effective_permission(handler)
            allowed = True
            reason = "permission"
            if event.is_private_chat() and not self._private_chat_enabled(handler):
                allowed = False
                reason = "private"
            elif permission == PERMISSION_FRAMEWORK_ADMIN:
                allowed = framework_admin
                reason = "framework_admin_permission"
            elif permission == PERMISSION_GROUP_ADMIN:
                if framework_admin:
                    allowed = True
                else:
                    if group_admin is None:
                        group_admin = await self._is_group_owner_or_admin(event)
                    allowed = group_admin
                    reason = "group_admin_permission"
            elif permission != PERMISSION_EVERYONE:
                allowed = False

            if not allowed:
                blocked.setdefault(
                    handler.handler_full_name,
                    {
                        "handler": handler,
                        "parsed_params": {},
                        "reason": reason,
                    },
                )
            elif permission == PERMISSION_GROUP_ADMIN:
                if framework_admin:
                    # Framework administrators do not need a group-role API
                    # lookup.  Replay immediately so a stale native ADMIN
                    # filter cannot make their command disappear.
                    if not readd_if_parseable(handler):
                        block_reparse_failure(handler)
                    continue
                # A handler can still be omitted by WakingCheck when an old
                # native ADMIN filter was injected before this manager took
                # control.  Once the custom group-role check says it is
                # allowed, mark it for the same parameter replay used by the
                # synchronous managed filter instead of silently losing the
                # command.
                blocked.setdefault(
                    handler.handler_full_name,
                    {
                        "handler": handler,
                        "parsed_params": {},
                        "reason": "group_lookup",
                    },
                )
            else:
                # Everyone/framework-admin handlers that were skipped by a
                # stale native filter are already authorized; replay their
                # command parser directly instead of silently losing them.
                if not readd_if_parseable(handler):
                    block_reparse_failure(handler)

    async def _command_permission_gate(self, event: AstrMessageEvent) -> bool:
        """Apply async fallbacks and prevent rejected commands reaching LLM."""

        original_call_llm = event.get_extra(
            BLOCKED_CALL_LLM_ORIGINAL_EXTRA_KEY,
        )
        if original_call_llm is None:
            original_call_llm = bool(getattr(event, "call_llm", False))
            event.set_extra(
                BLOCKED_CALL_LLM_ORIGINAL_EXTRA_KEY,
                original_call_llm,
            )

        activated_handlers = event.get_extra("activated_handlers", [])
        if not isinstance(activated_handlers, list):
            activated_handlers = []
        event.set_extra("activated_handlers", activated_handlers)
        blocked = event.get_extra(BLOCKED_COMMANDS_EXTRA_KEY, {}) or {}
        if not isinstance(blocked, dict):
            blocked = {}

        # Handler filters run before AstrBot applies per-session plugin
        # enablement. Remove provisional denials belonging to plugins disabled
        # in this conversation; from the session's perspective those commands
        # do not exist and must not suppress the default LLM or emit a private
        # policy notice.
        blocked_handlers = [
            entry.get("handler")
            for entry in blocked.values()
            if isinstance(entry, dict)
            and isinstance(entry.get("handler"), StarHandlerMetadata)
        ]
        if blocked_handlers:
            try:
                session_enabled_handlers = (
                    await SessionPluginManager.filter_handlers_by_session(
                        event,
                        blocked_handlers,
                    )
                )
            except Exception as exc:
                logger.debug(
                    f"[PermissionManager] 会话过滤失败，保持拒绝状态: {exc}",
                )
            else:
                session_enabled_names = {
                    handler.handler_full_name
                    for handler in session_enabled_handlers
                    if isinstance(handler, StarHandlerMetadata)
                }
                for name, entry in list(blocked.items()):
                    handler = entry.get("handler") if isinstance(entry, dict) else None
                    if (
                        isinstance(handler, StarHandlerMetadata)
                        and handler.handler_full_name not in session_enabled_names
                    ):
                        blocked.pop(name, None)

        await self._mark_unactivated_denied_commands(
            event,
            activated_handlers,
            blocked,
        )
        self._prune_shadowed_group_handlers(activated_handlers, blocked)
        # Handlers replayed by the scanner were appended after AstrBot's
        # normal priority ordering.  Restore the same execution order before
        # applying the async role fallback and cooldown gate.
        activated_handlers.sort(
            key=lambda handler: -handler.extras_configs.get("priority", 0),
        )

        # A synchronous filter deliberately denies unknown group roles first.
        # If this central gate is available, resolve those roles and re-add
        # only handlers still enabled for the current session.
        unresolved = [
            entry
            for entry in blocked.values()
            if isinstance(entry, dict) and entry.get("reason") == "group_lookup"
        ]
        if unresolved and not event.is_private_chat():
            if await self._is_group_owner_or_admin(event):
                candidates = [
                    entry.get("handler")
                    for entry in unresolved
                    if isinstance(entry.get("handler"), StarHandlerMetadata)
                ]
                candidate_names = {handler.handler_full_name for handler in candidates}
                try:
                    candidates = await SessionPluginManager.filter_handlers_by_session(
                        event,
                        candidates,
                    )
                except Exception as exc:
                    logger.debug(
                        f"[PermissionManager] 会话过滤失败，保持拒绝状态: {exc}",
                    )
                    for name in candidate_names:
                        entry = blocked.get(name)
                        if isinstance(entry, dict):
                            # Authorization already succeeded. Keep the
                            # command blocked on an infrastructure failure, but
                            # do not misreport it as a group-role denial.
                            entry["reason"] = "session_filter_failed"
                    candidates = []
                else:
                    enabled_names = {
                        handler.handler_full_name for handler in candidates
                    }
                    for name in candidate_names - enabled_names:
                        # The plugin is disabled in this conversation, so the
                        # provisional synchronous denial no longer belongs to
                        # the event and must not emit a policy notice.
                        blocked.pop(name, None)
                existing_names = {
                    handler.handler_full_name for handler in activated_handlers
                }
                parsed_params = event.get_extra("handlers_parsed_params", {})
                if not isinstance(parsed_params, dict):
                    parsed_params = {}
                    event.set_extra("handlers_parsed_params", parsed_params)
                for handler in candidates:
                    reparsed = self._reparse_command_handler(event, handler)
                    if reparsed is None:
                        entry = blocked.get(handler.handler_full_name)
                        if isinstance(entry, dict):
                            # The sender's group role has already been
                            # confirmed. A parameter/custom-filter replay
                            # failure must remain blocked so it cannot fall
                            # through to the LLM, but it is not a permission
                            # denial and therefore must not emit the group-admin
                            # notice.
                            entry["reason"] = "command_reparse_failed"
                        continue
                    if handler.handler_full_name not in existing_names:
                        activated_handlers.append(handler)
                        existing_names.add(handler.handler_full_name)
                    parsed_params[handler.handler_full_name] = reparsed
                    blocked.pop(handler.handler_full_name, None)
                activated_handlers.sort(
                    key=lambda handler: -handler.extras_configs.get("priority", 0),
                )
                self._prune_shadowed_group_handlers(activated_handlers, blocked)

        framework_admin = self._is_framework_admin(event)
        group_admin: bool | None = None
        filtered_handlers = []
        for handler in activated_handlers:
            if not self._is_command_handler(handler):
                filtered_handlers.append(handler)
                continue

            # Resolve from the live handler/config every time.  This also
            # observes a native PermissionTypeFilter inserted by /alter_cmd
            # after the permission manager was loaded.
            permission = self.perm_logic.get_effective_permission(handler)

            allowed = True
            reason = "permission"
            if event.is_private_chat() and not self._private_chat_enabled(handler):
                allowed = False
                reason = "private"
            elif permission == PERMISSION_FRAMEWORK_ADMIN:
                allowed = framework_admin
                reason = "framework_admin_permission"
            elif permission == PERMISSION_GROUP_ADMIN:
                if framework_admin:
                    allowed = True
                else:
                    if group_admin is None:
                        group_admin = await self._is_group_owner_or_admin(event)
                    allowed = group_admin
                    reason = "group_admin_permission"
            elif permission == PERMISSION_EVERYONE:
                allowed = True
            else:
                allowed = False

            if allowed:
                filtered_handlers.append(handler)
            else:
                blocked.setdefault(
                    handler.handler_full_name,
                    {
                        "handler": handler,
                        "parsed_params": {},
                        "reason": reason,
                    },
                )
        activated_handlers[:] = filtered_handlers
        event.set_extra(BLOCKED_COMMANDS_EXTRA_KEY, blocked)

        private_blocked = any(
            isinstance(entry, dict) and entry.get("reason") == "private"
            for entry in blocked.values()
        )
        group_admin_blocked = any(
            isinstance(entry, dict)
            and entry.get("reason") in {"group_admin_permission", "group_lookup"}
            for entry in blocked.values()
        )

        command_handlers = [
            handler
            for handler in activated_handlers
            if self._is_command_handler(handler)
        ]

        if command_handlers or (not blocked and not private_blocked):
            # A denied handler temporarily suppresses the default LLM during
            # WakingCheck.  If at least one command remains allowed (or every
            # provisional denial was resolved), restore the event-level value
            # captured before the first denial.  This is essential when one
            # message matches both an allowed and a rejected command handler.
            event.should_call_llm(bool(original_call_llm))
            return True

        # A recognized but rejected command must never fall through to the
        # default LLM. At most one configured notice is sent for the event.
        event.should_call_llm(True)
        event.clear_result()
        notice_message = ""
        notice_label = ""
        if private_blocked and self._private_chat_notify_enabled():
            notice_message = self._private_chat_denied_message()
            notice_label = "私聊禁用"
        elif group_admin_blocked and self._group_admin_notify_enabled():
            notice_message = self._group_admin_denied_message()
            notice_label = "群管理员权限不足"
        if notice_message:
            try:
                await event.send(MessageChain().message(notice_message))
            except Exception as exc:
                # A failed notice must not turn a policy rejection into an
                # unhandled event that could be processed by the default LLM.
                logger.debug(
                    f"[PermissionManager] {notice_label}提示发送失败: {exc}",
                )
        event.stop_event()
        return False

    def _get_cooldown_seconds(self) -> float:
        """Read and normalize the shared command cooldown duration.

        Returns:
            A positive cooldown duration in seconds, or 0 when disabled or
            invalid.
        """
        raw_value = self.config.get(
            "global_command_cooldown_seconds",
            self.config.get("global_command_cooldown", 0),
        )
        if isinstance(raw_value, bool):
            return 0.0
        try:
            value = float(raw_value or 0)
        except (OverflowError, TypeError, ValueError):
            return 0.0
        if not math.isfinite(value) or value <= 0:
            return 0.0
        return value

    def _get_cooldown_mode(self) -> str:
        """Return the configured behavior for a hit cooldown window.

        Returns:
            ``queue`` for queued hits; otherwise ``ignore``.
        """
        mode = str(self.config.get("cooldown_hit_mode", "ignore")).strip().lower()
        return "queue" if mode in {"queue", "排队"} else "ignore"

    @staticmethod
    def _get_cooldown_scope(event: AstrMessageEvent) -> str:
        """Build a platform-aware scope shared by all commands in one chat.

        Args:
            event: Incoming AstrBot message event.

        Returns:
            A stable scope key for one platform chat or private sender.
        """
        platform_id = str(
            event.get_platform_id() or event.get_platform_name() or "unknown",
        )
        raw_group_id = event.get_group_id()
        group_id = "" if raw_group_id is None else str(raw_group_id).strip()
        if group_id and not event.is_private_chat():
            return f"{platform_id}:group:{group_id}"

        raw_sender_id = event.get_sender_id()
        sender_id = "" if raw_sender_id is None else str(raw_sender_id).strip()
        private_scope = sender_id or str(
            getattr(event, "unified_msg_origin", "") or "unknown",
        )
        return f"{platform_id}:private:{private_scope}"

    @staticmethod
    def _is_command_handler(handler: StarHandlerMetadata) -> bool:
        """Return whether a handler represents an executable command.

        Args:
            handler: Handler metadata from the waking stage.

        Returns:
            True when the handler has at least one direct CommandFilter.
        """
        return any(
            isinstance(event_filter, (CommandFilter, CommandGroupFilter))
            for event_filter in handler.event_filters
        )

    async def _global_command_cooldown_gate(self, event: AstrMessageEvent):
        """Apply one cooldown slot to every command in the current chat scope.

        The waking stage has already evaluated command, permission, and custom
        filters by the time this high-priority handler runs.  Reading its
        activated handler list therefore avoids consuming a slot for invalid or
        unauthorized command attempts.

        Args:
            event: Incoming AstrBot message event.

        Returns:
            None. The event is either allowed, queued, or silently stopped.
        """
        cooldown_seconds = self._get_cooldown_seconds()
        if cooldown_seconds <= 0:
            return

        activated_handlers = event.get_extra("activated_handlers", []) or []
        if not any(self._is_command_handler(handler) for handler in activated_handlers):
            return

        scope = self._get_cooldown_scope(event)
        cooldown_locks = getattr(self, "_cooldown_locks", None)
        if cooldown_locks is None:
            cooldown_locks = {}
            self._cooldown_locks = cooldown_locks
        lock = cooldown_locks.setdefault(scope, asyncio.Lock())

        async with lock:
            now = time.monotonic()
            next_available = self._cooldown_next_available.get(scope, 0.0)

            # Drop expired scopes once the cache becomes large enough to
            # avoid retaining one entry forever for every group that has
            # ever used a bot.
            if len(self._cooldown_next_available) > 1024:
                self._cooldown_next_available = {
                    key: available_at
                    for key, available_at in self._cooldown_next_available.items()
                    if available_at > now
                }

            if self._get_cooldown_mode() == "ignore":
                if now < next_available:
                    event.should_call_llm(True)
                    event.clear_result()
                    event.stop_event()
                    return
                self._cooldown_next_available[scope] = now + cooldown_seconds
                return

            start_at = max(now, next_available)
            self._cooldown_next_available[scope] = start_at + cooldown_seconds
        wait_seconds = start_at - now
        if wait_seconds > 0:
            await asyncio.sleep(wait_seconds)

    @filter.custom_filter(WakeCommandFilter)
    @filter.event_message_type(
        filter.EventMessageType.ALL,
        priority=GLOBAL_COOLDOWN_HANDLER_PRIORITY,
    )
    async def _cooldown_gate_handler(self, event: AstrMessageEvent):
        if not await self._command_permission_gate(event):
            return
        await self._global_command_cooldown_gate(event)

    @filter.on_plugin_loaded()
    async def _on_plugin_loaded(self, metadata: Any):
        """Protect commands registered after the initial startup pass."""
        if getattr(metadata, "name", None) == PLUGIN_NAME:
            return
        try:
            await self.perm_logic.apply_all_permissions()
        except Exception as exc:
            logger.debug(f"[PermissionManager] 新插件权限同步失败: {exc}")

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
            if (
                plugin.name == plugin_name
                and plugin.logo_path
                and os.path.exists(plugin.logo_path)
            ):
                logo_path = plugin.logo_path
                break
        if logo_path:
            return await send_file(logo_path)

        default_logo = os.path.join(os.path.dirname(__file__), "logo.png")
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
        try:
            req = await request.json
            await self.perm_logic.set_command_permission(
                plugin_name,
                handler_name,
                req.get("permission"),
            )
            return jsonify({"success": True})
        except Exception as exc:
            return jsonify({"success": False, "message": str(exc)}), 400

    async def api_set_private_chat(self, plugin_name, handler_name):
        try:
            req = await request.json
            if not isinstance(req, dict) or not isinstance(req.get("enabled"), bool):
                raise ValueError("enabled 必须是布尔值")
            await self.perm_logic.set_command_private_chat(
                plugin_name,
                handler_name,
                req["enabled"],
            )
            return jsonify({"success": True})
        except Exception as exc:
            return jsonify({"success": False, "message": str(exc)}), 400

    async def api_batch_perm(self, plugin_name):
        try:
            req = await request.json
            perm = req.get("permission")
            cmds = self.perm_logic._get_all_commands_by_plugin().get(plugin_name, [])
            if not cmds:
                raise ValueError("未找到该插件或其命令")
            for handler, _, _, _ in cmds:
                await self.perm_logic.set_command_permission(
                    plugin_name,
                    handler.handler_name,
                    perm,
                )
            return jsonify({"success": True})
        except Exception as exc:
            return jsonify({"success": False, "message": str(exc)}), 400

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
        if not handler:
            return jsonify({"success": False, "message": "未找到命令处理器"})
        if not self.perm_logic._apply_command_identity(handler, aliases=aliases):
            return jsonify({"success": False, "message": "命令处理器不支持设置别名"})

        return jsonify({"success": True})

    @filter.command_group("perm")
    def perm(self):
        pass

    @filter.permission_type(filter.PermissionType.ADMIN)
    @perm.command("list")
    async def list_cmd(self, event: AstrMessageEvent):
        plugins = await self.perm_logic.get_all_plugins_api()
        msg = "📋 插件列表 (可在 WebUI 管理)：\n" + "\n".join(
            [f"🔹 {p['name']} ({p['total_commands']} cmds)" for p in plugins]
        )
        yield event.plain_result(msg)
