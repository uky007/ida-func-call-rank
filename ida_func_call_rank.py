"""
ida_func_call_rank.py - IDAPython plugin "Function Call Rank"

Adds a sortable, Ghidra-like function call-ranking table to IDA Pro.
Counts are based on static IDA xrefs (direct calls only: fl_CF / fl_CN).
This is a static triage heuristic, not a runtime profiler.

Project:   ida-func-call-rank
License:   MIT License
Compat:    IDA 7.x / 8.x / 9.x (IDAPython 3)
"""

import csv
import os

import ida_funcs
import ida_idaapi
import ida_kernwin
import ida_name
import ida_segment
import ida_xref
import idautils
import idc

# ---------------------------------------------------------------------------
# Plugin metadata
# ---------------------------------------------------------------------------

PLUGIN_NAME    = "Function Call Rank"
PLUGIN_COMMENT = "Show a sortable function call-ranking table (triage view)."
PLUGIN_HELP    = (
    "Static xref-based function call ranking. Sorts by Unique Callers / "
    "Calls In / Calls Out. Useful for early reverse-engineering triage."
)
PLUGIN_HOTKEY  = "Ctrl-Shift-C"
WINDOW_TITLE   = "Function Call Rank"
ACTION_PREFIX  = "func_call_rank:"

# ---------------------------------------------------------------------------
# Compatibility helpers (IDA 7.x / 8.x / 9.x)
# ---------------------------------------------------------------------------

def _get_segm_name(seg):
    if seg is None:
        return ""
    try:
        name = ida_segment.get_segm_name(seg)
    except TypeError:
        # Some very old signatures accept (seg, flags)
        name = ida_segment.get_segm_name(seg, 0)
    return name or ""


def _seg_is_extern(seg):
    return seg is not None and seg.type == ida_segment.SEG_XTRN


def _is_lib_func(func):
    return bool(func.flags & ida_funcs.FUNC_LIB)


def _is_thunk_func(func):
    return bool(func.flags & ida_funcs.FUNC_THUNK)


def _get_idb_path():
    try:
        import ida_loader
        path = ida_loader.get_path(ida_loader.PATH_TYPE_IDB)
        if path:
            return path
    except Exception:
        pass
    try:
        return idc.get_idb_path() or ""
    except Exception:
        return ""


def _ask_file_save(default_name):
    # Different IDA versions used ask_file / AskFile etc.
    try:
        path = ida_kernwin.ask_file(True, default_name, "Save CSV")
        if path:
            return path
    except Exception:
        pass
    try:  # very old fallback
        return ida_kernwin.askfile_c(1, default_name, "Save CSV")  # type: ignore[attr-defined]
    except Exception:
        return None


def _msg(text):
    try:
        ida_kernwin.msg(text + "\n")
    except Exception:
        print(text)


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

CALL_XREF_TYPES = frozenset({
    ida_xref.fl_CF,  # call far
    ida_xref.fl_CN,  # call near
})


class FunctionCallStats(object):
    __slots__ = (
        "ea",
        "name",
        "segment",
        "size",
        "is_lib",
        "is_thunk",
        "is_extern",
        "calls_in",
        "unique_callers",
        "calls_out",
        "unique_callees",
        "recursive_calls",
        "unknown_callees",
    )

    def __init__(self, func):
        self.ea = func.start_ea
        self.name = ida_name.get_name(func.start_ea) or ""
        seg = ida_segment.getseg(func.start_ea)
        self.segment = _get_segm_name(seg)
        self.size = func.end_ea - func.start_ea
        self.is_lib = _is_lib_func(func)
        self.is_thunk = _is_thunk_func(func)
        self.is_extern = _seg_is_extern(seg)
        self.calls_in = 0
        self.unique_callers = set()
        self.calls_out = 0
        self.unique_callees = set()
        self.recursive_calls = 0
        self.unknown_callees = 0

    @property
    def unique_callers_count(self):
        return len(self.unique_callers)

    @property
    def unique_callees_count(self):
        return len(self.unique_callees)

    @property
    def flags_str(self):
        bits = []
        if self.is_lib:
            bits.append("lib")
        if self.is_thunk:
            bits.append("thunk")
        if self.is_extern:
            bits.append("extern")
        return ",".join(bits)


class CallRankOptions(object):
    def __init__(self):
        self.exclude_library = True
        self.exclude_thunks = True
        self.exclude_imports = True
        self.exclude_zero_callers = False

    def passes_filter(self, stat):
        if self.exclude_library and stat.is_lib:
            return False
        if self.exclude_thunks and stat.is_thunk:
            return False
        if self.exclude_imports and stat.is_extern:
            return False
        if self.exclude_zero_callers and stat.calls_in == 0:
            return False
        return True

    def status_text(self):
        hidden = []
        if self.exclude_library:
            hidden.append("lib")
        if self.exclude_thunks:
            hidden.append("thunk")
        if self.exclude_imports:
            hidden.append("import")
        bits = ["direct calls only"]
        if hidden:
            bits.append("/".join(hidden) + " hidden")
        if self.exclude_zero_callers:
            bits.append("zero-callers hidden")
        return ", ".join(bits)


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

def _iter_code_xrefs_from(ea):
    """Yield (xref_type, target_ea) for every non-flow code xref from `ea`.

    Why we don't use XREF_CODE / XREF_NOFLOW flags: those constants are
    inconsistent across IDA versions (some builds expose XREF_FAR / XREF_DATA
    only on `xrefblk_t.first_from`). Instead we enumerate every xref and
    filter in Python: code-only, and exclude `fl_F` (the next-instruction
    flow edge).
    """
    xb = ida_xref.xrefblk_t()
    ok = xb.first_from(ea, 0)  # 0 == XREF_ALL on every build we care about
    fl_F = ida_xref.fl_F
    while ok:
        if xb.iscode and xb.type != fl_F:
            yield xb.type, xb.to
        ok = xb.next_from()


def scan_all_functions():
    """Walk every function and accumulate direct call statistics.

    Returns a dict keyed by function start_ea -> FunctionCallStats.
    """
    stats = {}

    func_eas = list(idautils.Functions())
    total = len(func_eas)
    for ea in func_eas:
        f = ida_funcs.get_func(ea)
        if not f:
            continue
        stats[f.start_ea] = FunctionCallStats(f)

    progress_step = max(1, total // 10) if total else 1
    last_bucket = -1

    for idx, caller_ea in enumerate(list(stats.keys())):
        if total and idx // progress_step != last_bucket:
            last_bucket = idx // progress_step
            _msg("[func-call-rank] scanning %d / %d functions..." %
                 (idx, total))

        caller_stat = stats[caller_ea]
        for chunk_start, chunk_end in idautils.Chunks(caller_ea):
            for head in idautils.Heads(chunk_start, chunk_end):
                for xref_type, target_ea in _iter_code_xrefs_from(head):
                    if xref_type not in CALL_XREF_TYPES:
                        continue

                    caller_stat.calls_out += 1

                    callee_func = ida_funcs.get_func(target_ea)
                    if callee_func is None:
                        caller_stat.unknown_callees += 1
                        continue

                    callee_ea = callee_func.start_ea
                    caller_stat.unique_callees.add(callee_ea)

                    callee_stat = stats.get(callee_ea)
                    if callee_stat is None:
                        callee_stat = FunctionCallStats(callee_func)
                        stats[callee_ea] = callee_stat

                    callee_stat.calls_in += 1
                    callee_stat.unique_callers.add(caller_ea)

                    if caller_ea == callee_ea:
                        caller_stat.recursive_calls += 1

    if total:
        _msg("[func-call-rank] scan complete: %d functions" % total)
    return stats


def build_rows(stats, options):
    """Filter and sort the stats dict; return a list[FunctionCallStats]."""
    rows = [s for s in stats.values() if options.passes_filter(s)]
    rows.sort(
        key=lambda s: (
            s.unique_callers_count,
            s.calls_in,
            s.calls_out,
            -s.ea,
        ),
        reverse=True,
    )
    return rows


# ---------------------------------------------------------------------------
# CSV export
# ---------------------------------------------------------------------------

CSV_HEADER = [
    "ea",
    "name",
    "segment",
    "size",
    "flags",
    "unique_callers",
    "calls_in",
    "unique_callees",
    "calls_out",
    "recursive_calls",
    "unknown_callees",
]


def _default_csv_path():
    idb = _get_idb_path()
    if idb:
        base, _ext = os.path.splitext(idb)
        return base + "_function_call_rank.csv"
    return "function_call_rank.csv"


def export_rows_to_csv(rows, path):
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(CSV_HEADER)
        for r in rows:
            writer.writerow([
                "0x%X" % r.ea,
                r.name,
                r.segment,
                r.size,
                r.flags_str,
                r.unique_callers_count,
                r.calls_in,
                r.unique_callees_count,
                r.calls_out,
                r.recursive_calls,
                r.unknown_callees,
            ])


# ---------------------------------------------------------------------------
# Chooser UI
# ---------------------------------------------------------------------------

class FunctionCallRankChooser(ida_kernwin.Choose):

    COLS = [
        ["Unique Callers", 14 | ida_kernwin.Choose.CHCOL_DEC],
        ["Calls In",       10 | ida_kernwin.Choose.CHCOL_DEC],
        ["Unique Callees", 14 | ida_kernwin.Choose.CHCOL_DEC],
        ["Calls Out",      10 | ida_kernwin.Choose.CHCOL_DEC],
        ["EA",             16 | ida_kernwin.Choose.CHCOL_EA],
        ["Name",           40 | ida_kernwin.Choose.CHCOL_PLAIN],
        ["Segment",        12 | ida_kernwin.Choose.CHCOL_PLAIN],
        ["Size",           10 | ida_kernwin.Choose.CHCOL_DEC],
        ["Flags",          14 | ida_kernwin.Choose.CHCOL_PLAIN],
    ]

    def __init__(self):
        flags = (
            ida_kernwin.Choose.CH_CAN_REFRESH
            | ida_kernwin.Choose.CH_RESTORE
        )
        ida_kernwin.Choose.__init__(
            self,
            WINDOW_TITLE,
            self.COLS,
            flags=flags,
        )
        self.options = CallRankOptions()
        self.rows = []
        self._stats = {}
        self._scan_and_refilter()

    # ---- data lifecycle ----

    def _scan_and_refilter(self):
        ida_kernwin.show_wait_box("HIDECANCEL\nScanning function call xrefs...")
        try:
            self._stats = scan_all_functions()
            self.rows = build_rows(self._stats, self.options)
        finally:
            ida_kernwin.hide_wait_box()
        self._update_title()

    def _refilter_only(self):
        self.rows = build_rows(self._stats, self.options)
        self._update_title()

    def _update_title(self):
        total = len(self._stats)
        shown = len(self.rows)
        hidden = total - shown
        # NOTE: ida_kernwin.Choose reads `self.title` only at construction
        # time on most IDA builds, so re-assigning it here will not refresh
        # the tab caption. We log the breakdown to the Output window every
        # time so the user can still see filter impact at a glance.
        try:
            self.title = "%s - %d/%d (%d hidden), %s" % (
                WINDOW_TITLE,
                shown,
                total,
                hidden,
                self.options.status_text(),
            )
        except Exception:
            pass
        _msg(
            "[func-call-rank] %d / %d functions shown (%d hidden by filters) -- %s"
            % (shown, total, hidden, self.options.status_text())
        )

    # ---- Choose callbacks ----

    def OnGetSize(self):
        return len(self.rows)

    def OnGetLine(self, n):
        r = self.rows[n]
        return [
            str(r.unique_callers_count),
            str(r.calls_in),
            str(r.unique_callees_count),
            str(r.calls_out),
            "0x%X" % r.ea,
            r.name,
            r.segment,
            str(r.size),
            r.flags_str,
        ]

    def OnSelectLine(self, n):
        if 0 <= n < len(self.rows):
            ida_kernwin.jumpto(self.rows[n].ea)
        # Newer IDA expects a tuple/list with a "result" code; older IDA
        # accepts the bare constant. Return a tuple to satisfy both.
        return (ida_kernwin.Choose.NOTHING_CHANGED, )

    def OnRefresh(self, n):
        self._scan_and_refilter()
        try:
            return [ida_kernwin.Choose.ALL_CHANGED] + self.adjust_last_item(n)
        except Exception:
            return ida_kernwin.Choose.ALL_CHANGED

    # ---- external helpers ----

    def export_csv(self):
        path = _ask_file_save(_default_csv_path())
        if not path:
            return
        try:
            export_rows_to_csv(self.rows, path)
            _msg("[func-call-rank] CSV exported: %s (%d rows)" %
                 (path, len(self.rows)))
        except OSError as e:
            ida_kernwin.warning("Failed to write CSV: %s" % e)

    def toggle_filter(self, name):
        if not hasattr(self.options, name):
            return
        setattr(self.options, name, not getattr(self.options, name))
        self._refilter_only()
        ida_kernwin.refresh_chooser(WINDOW_TITLE)


# ---------------------------------------------------------------------------
# Context-menu actions
# ---------------------------------------------------------------------------

def _live_chooser():
    return FunctionCallRankPlugin.view


class _ChooserActionHandler(ida_kernwin.action_handler_t):
    def __init__(self, callback):
        ida_kernwin.action_handler_t.__init__(self)
        self._callback = callback

    def activate(self, ctx):
        chooser = _live_chooser()
        if chooser is None:
            return 0
        try:
            self._callback(chooser)
        except Exception as e:
            _msg("[func-call-rank] action failed: %r" % e)
        return 1

    def update(self, ctx):
        title = getattr(ctx, "widget_title", "") or ""
        if title == WINDOW_TITLE:
            return ida_kernwin.AST_ENABLE_FOR_WIDGET
        return ida_kernwin.AST_DISABLE_FOR_WIDGET


def _act_rescan(chooser):
    chooser._scan_and_refilter()
    ida_kernwin.refresh_chooser(WINDOW_TITLE)


def _act_export_csv(chooser):
    chooser.export_csv()


def _act_toggle_lib(chooser):
    chooser.toggle_filter("exclude_library")


def _act_toggle_thunk(chooser):
    chooser.toggle_filter("exclude_thunks")


def _act_toggle_import(chooser):
    chooser.toggle_filter("exclude_imports")


def _act_toggle_zero(chooser):
    chooser.toggle_filter("exclude_zero_callers")


_ACTION_DEFS = [
    ("rescan",        "Rescan",                   _act_rescan),
    ("export_csv",    "Export CSV...",            _act_export_csv),
    ("toggle_lib",    "Toggle hide library",      _act_toggle_lib),
    ("toggle_thunk",  "Toggle hide thunks",       _act_toggle_thunk),
    ("toggle_import", "Toggle hide imports",      _act_toggle_import),
    ("toggle_zero",   "Toggle hide zero callers", _act_toggle_zero),
]


class _PopupHook(ida_kernwin.UI_Hooks):
    def finish_populating_widget_popup(self, widget, popup):
        try:
            title = ida_kernwin.get_widget_title(widget)
        except Exception:
            title = ""
        if title != WINDOW_TITLE:
            return
        for key, _label, _cb in _ACTION_DEFS:
            ida_kernwin.attach_action_to_popup(
                widget,
                popup,
                ACTION_PREFIX + key,
                "Function Call Rank/",
            )


# ---------------------------------------------------------------------------
# Plugin lifecycle
# ---------------------------------------------------------------------------

class FunctionCallRankPlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_FIX
    comment = PLUGIN_COMMENT
    help = PLUGIN_HELP
    wanted_name = PLUGIN_NAME
    wanted_hotkey = PLUGIN_HOTKEY

    # Module-level singletons so values survive plugin re-entry.
    view = None
    _hook = None
    _registered = False

    def init(self):
        if not FunctionCallRankPlugin._registered:
            self._register_actions()
            FunctionCallRankPlugin._registered = True
        if FunctionCallRankPlugin._hook is None:
            FunctionCallRankPlugin._hook = _PopupHook()
            FunctionCallRankPlugin._hook.hook()
        return ida_idaapi.PLUGIN_KEEP

    def run(self, arg):
        if FunctionCallRankPlugin.view is None:
            FunctionCallRankPlugin.view = FunctionCallRankChooser()
        FunctionCallRankPlugin.view.Show(False)
        try:
            widget = ida_kernwin.find_widget(WINDOW_TITLE)
            if widget is not None:
                ida_kernwin.activate_widget(widget, True)
        except Exception:
            pass

    def term(self):
        if FunctionCallRankPlugin._hook is not None:
            try:
                FunctionCallRankPlugin._hook.unhook()
            except Exception:
                pass
            FunctionCallRankPlugin._hook = None
        for key, _label, _cb in _ACTION_DEFS:
            try:
                ida_kernwin.unregister_action(ACTION_PREFIX + key)
            except Exception:
                pass
        FunctionCallRankPlugin._registered = False
        FunctionCallRankPlugin.view = None

    # ---- internals ----

    def _register_actions(self):
        for key, label, cb in _ACTION_DEFS:
            action_id = ACTION_PREFIX + key
            handler = _ChooserActionHandler(cb)
            desc = ida_kernwin.action_desc_t(
                action_id,
                label,
                handler,
                None,
                label,
                -1,
            )
            ida_kernwin.unregister_action(action_id)
            ida_kernwin.register_action(desc)


def PLUGIN_ENTRY():
    return FunctionCallRankPlugin()
