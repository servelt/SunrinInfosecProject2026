"""Development-only model request ledger without a fixed function count.

The caller must use ``start_attempt`` before sending each physical request.
That method persists the attempt before returning. This file does not replace
the frozen Blind 2 ledger or authorize a Blind 3 execution contract.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import time
from uuid import uuid4


DIRECTION_ROLE = "direction_generator"
SP_ROLES = frozenset({"sp_generation", "sp_verifier", "poc_generator"})
HP_ROLES = frozenset({"function_analysis", "assertion_generator"})
FUNCTION_ROLES = SP_ROLES | HP_ROLES
WORK_KINDS = frozenset({"DIRECTION", "SCAN", "SP_VERIFIER", "POV", "ASSERTION"})
TERMINAL_PENDING_STATES = frozenset({
    "INCOMPLETE_PRE_SEND_MODEL_TURN",
    "INCOMPLETE_UNCERTAIN_REMOTE_STATE",
    "INCOMPLETE_PRODUCT_RESPONSE",
    "INCOMPLETE_PHYSICAL_STOP",
})
PHYSICAL_STOP_REASONS = frozenset({
    "STOPPED_UNCERTAIN_PROCESS",
    "STOPPED_PHYSICAL_CAP_UNPROVEN",
    "STOPPED_CLEANUP_INCOMPLETE",
})
NO_OPPORTUNITY_PHYSICAL_STOP = "NO_OPPORTUNITY_PHYSICAL_STOP"
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_TURN_ID = re.compile(r"L[0-9]{6,}\Z")
PER_FUNCTION_V2_PROFILE = "PER_FUNCTION_V2"
GLOBAL_ONLY_DEV_PROFILE = "GLOBAL_ONLY_DEV"
_CHECKPOINT_KINDS = {
    PER_FUNCTION_V2_PROFILE: "DEV_GLOBAL_REQUEST_LEDGER_V2",
    GLOBAL_ONLY_DEV_PROFILE: "DEV_GLOBAL_REQUEST_LEDGER_GLOBAL_ONLY_V1",
}


def _reject_linked_checkpoint_path(path: Path) -> None:
    if path.is_symlink() or any(parent.is_symlink() for parent in path.parents):
        raise ValueError("development checkpoint path is linked")
    if not path.is_absolute():
        raise ValueError("development checkpoint path must be absolute")
    if ".." in path.parts or path != path.resolve(strict=False):
        raise ValueError("development checkpoint path must be canonical")


@contextmanager
def _checkpoint_lock(path: Path):
    """Serialize cooperating writers on a stable lock inode, never the replaced JSON."""
    lock_path = path.with_name(path.name + ".lock")
    _reject_linked_checkpoint_path(path)
    _reject_linked_checkpoint_path(lock_path)
    try:
        fd = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    except OSError as exc:
        raise ValueError("development checkpoint lock unavailable") from exc
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or
                stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
            raise ValueError("development checkpoint lock is unsafe")
        deadline = time.monotonic() + 10.0
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise ValueError("development checkpoint lock timed out") from None
                time.sleep(0.01)
        current = lock_path.lstat()
        if (not stat.S_ISREG(current.st_mode) or
                (current.st_dev, current.st_ino) != (info.st_dev, info.st_ino)):
            raise ValueError("development checkpoint lock was replaced")
        yield
    finally:
        os.close(fd)


class DevelopmentBudgetExhausted(ValueError):
    """A global physical, logical, or wall credit is exhausted."""


@dataclass(frozen=True)
class DevelopmentBudget:
    # These global values must come from an explicit development contract.
    physical_max: int
    logical_max: int
    retries_max: int
    wall_seconds: float
    initial_starts_required: int
    # Prior Blind 2 values are comparison defaults, not FBV2 recommendations.
    sp_per_function: int = 4
    hp_per_function: int = 4
    combined_per_function: int = 8
    hp_analysis_per_function: int = 3
    hp_assertion_per_function: int = 1
    direction_turns_per_scope: int = 1
    # The new profile only removes per-function role limits; it never relaxes
    # global start accounting, Direction identity, or request identity checks.
    profile: str = PER_FUNCTION_V2_PROFILE

    def __post_init__(self) -> None:
        if self.profile not in _CHECKPOINT_KINDS:
            raise ValueError("unknown development budget profile")
        for name in ("physical_max", "logical_max", "retries_max",
                     "initial_starts_required", "sp_per_function",
                     "hp_per_function", "combined_per_function",
                     "hp_analysis_per_function", "hp_assertion_per_function",
                     "direction_turns_per_scope"):
            value = getattr(self, name)
            if type(value) is not int or value < (0 if name == "retries_max" else 1):
                raise ValueError(f"invalid development limit: {name}")
        if (not isinstance(self.wall_seconds, (int, float)) or
                isinstance(self.wall_seconds, bool) or
                not math.isfinite(self.wall_seconds) or self.wall_seconds <= 0 or
                self.initial_starts_required > self.physical_max or
                self.profile == PER_FUNCTION_V2_PROFILE and (
                    self.hp_analysis_per_function + self.hp_assertion_per_function <
                        self.hp_per_function or
                    max(self.sp_per_function, self.hp_per_function) >
                        self.combined_per_function)):
            raise ValueError("inconsistent development limits")

    def checkpoint_budget(self) -> dict:
        """Keep old V2 checkpoint budgets byte-schema compatible."""
        result = asdict(self)
        if self.profile == PER_FUNCTION_V2_PROFILE:
            result.pop("profile")
        return result


@dataclass
class DevelopmentRequestLedger:
    budget: DevelopmentBudget
    checkpoint_path: Path
    started_at: float
    logical: int = 0
    physical: int = 0
    retries: int = 0
    direction_scopes: list[str] = field(default_factory=list)
    direction_counts: dict[str, int] = field(default_factory=dict)
    selected_functions: list[str] = field(default_factory=list)
    function_counts: dict[str, dict[str, int]] = field(default_factory=dict)
    function_states: dict[str, str] = field(default_factory=dict)
    no_opportunity: dict[str, str] = field(default_factory=dict)
    pending_work: list[dict[str, str]] = field(default_factory=list)
    turns: list[dict[str, str]] = field(default_factory=list)
    attempts: list[dict] = field(default_factory=list)
    active_turn: dict | None = None
    tainted: bool = False

    @classmethod
    def create(cls, budget: DevelopmentBudget, checkpoint_path: Path,
               *, started_at: float | None = None) -> "DevelopmentRequestLedger":
        _reject_linked_checkpoint_path(checkpoint_path)
        if checkpoint_path.exists() or checkpoint_path.is_symlink():
            raise FileExistsError(checkpoint_path)
        ledger = cls(budget, checkpoint_path,
                     time.time() if started_at is None else started_at)
        ledger._validate()
        ledger.checkpoint()
        return ledger

    def wall(self, *, now: float | None = None) -> None:
        timestamp = time.time() if now is None else now
        if (not math.isfinite(timestamp) or
                timestamp - self.started_at >= self.budget.wall_seconds):
            raise DevelopmentBudgetExhausted("development wall limit reached")

    def _validate(self) -> None:
        if (not math.isfinite(self.started_at) or
                any(type(value) is not int or value < 0 for value in
                    (self.logical, self.physical, self.retries)) or
                self.logical > self.budget.logical_max or
                self.physical > self.budget.physical_max or
                self.retries > self.budget.retries_max or
                self.physical > self.logical + self.retries or
                len(self.turns) != self.logical or
                self.physical != len(self.attempts) or
                self.retries != sum(row.get("retry") is True for row in self.attempts) or
                len(self.direction_scopes) != len(set(self.direction_scopes)) or
                len(self.selected_functions) != len(set(self.selected_functions)) or
                set(self.direction_scopes) != set(self.direction_counts) or
                set(self.selected_functions) != set(self.function_counts) or
                set(self.selected_functions) != set(self.function_states) or
                set(self.selected_functions) & set(self.no_opportunity) or
                len({row["id"] for row in self.pending_work}) != len(self.pending_work)):
            raise ValueError("development checkpoint counters or identities invalid")
        for row in self.pending_work:
            if (type(row) is not dict or set(row) !=
                    {"id", "scope_id", "work_kind", "state", "reason"} or
                    not isinstance(row.get("id"), str) or not row["id"] or
                    row.get("scope_id") not in self.direction_counts and
                    row.get("scope_id") not in self.function_counts or
                    row.get("work_kind") not in WORK_KINDS or
                    row.get("state") not in TERMINAL_PENDING_STATES | {"PENDING_BUDGET"} or
                    not isinstance(row.get("reason"), str)):
                raise ValueError("development pending work record invalid")
            if row["state"] == "PENDING_BUDGET" and _TURN_ID.fullmatch(row["id"]):
                raise ValueError("reserved turn identity in ordinary pending work")
        expected_direction = {scope: 0 for scope in self.direction_scopes}
        expected_function = {scope: {} for scope in self.selected_functions}
        turn_by_id: dict[str, dict] = {}
        for index, turn in enumerate(self.turns, 1):
            turn_id = f"L{index:06d}"
            role, scope_id = turn.get("role"), turn.get("scope_id")
            if (turn.get("id") != turn_id or
                    not _SHA.fullmatch(str(turn.get("hash", ""))) or
                    turn.get("status") not in {
                        "ACTIVE", "COMPLETED", "INCOMPLETE_BUDGET",
                        "INCOMPLETE_INTERRUPTED", "INCOMPLETE_PRODUCT_RESPONSE"}):
                raise ValueError("development logical turn history invalid")
            if role == DIRECTION_ROLE:
                if scope_id not in expected_direction:
                    raise ValueError("development Direction turn scope invalid")
                expected_direction[scope_id] += 1
            elif role in FUNCTION_ROLES:
                if scope_id not in expected_function:
                    raise ValueError("development function turn scope invalid")
                counts = expected_function[scope_id]
                counts[role] = counts.get(role, 0) + 1
            else:
                raise ValueError("development logical turn role invalid")
            if (turn["status"] == "ACTIVE") != (
                    self.active_turn is not None and
                    self.active_turn.get("id") == turn_id):
                raise ValueError("development active logical turn history invalid")
            turn_by_id[turn_id] = turn
        pending_by_id = {row["id"]: row for row in self.pending_work}
        for row in self.pending_work:
            turn = turn_by_id.get(row["id"])
            if row["state"] == "PENDING_BUDGET":
                if turn is not None:
                    raise ValueError("interrupted model turn cannot be budget pending")
                continue
            if row["state"] == "INCOMPLETE_PHYSICAL_STOP":
                scope_id = row["scope_id"]
                if (row["id"] != "physical-stop:" + scope_id or
                        scope_id not in self.function_states or
                        self.function_states[scope_id] != "INCOMPLETE_PHYSICAL_STOP" or
                        row["work_kind"] != "SCAN" or
                        row["reason"] not in PHYSICAL_STOP_REASONS or
                        turn is not None):
                    raise ValueError("physical stop and selected function disagree")
                continue
            if row["state"] == "INCOMPLETE_PRODUCT_RESPONSE":
                matching = [attempt for attempt in self.attempts
                            if attempt["turn_id"] == row["id"]]
                last = matching[-1] if matching else None
                if (turn is None or turn["status"] != row["state"] or
                        row["scope_id"] != turn["scope_id"] or
                        row["work_kind"] != "SCAN" or
                        self.function_states.get(row["scope_id"]) !=
                            "INCOMPLETE_PRODUCT_RESPONSE" or
                        last is None or last["status"] != "ERROR" or
                        last.get("server_terminal_status") != "completed" or
                        not isinstance(last.get("app_server_turn_id"), str) or
                        not last["app_server_turn_id"] or
                        not isinstance(last.get("product_response_error_type"), str) or
                        not _SHA.fullmatch(str(last.get(
                            "product_response_error_sha256", ""))) or
                        last["request_hash"] != turn["hash"]):
                    raise ValueError("completed-server product error receipt invalid")
                continue
            if (turn is None or not turn["status"].startswith("INCOMPLETE") or
                    row["scope_id"] != turn["scope_id"] or
                    row["work_kind"] != ("DIRECTION" if turn["role"] == DIRECTION_ROLE
                                         else "SCAN") or
                    row["state"] != ("INCOMPLETE_UNCERTAIN_REMOTE_STATE" if
                                     any(attempt.get("turn_id") == turn["id"]
                                         for attempt in self.attempts) else
                                     "INCOMPLETE_PRE_SEND_MODEL_TURN")):
                raise ValueError("interrupted pending work and turn history disagree")
        if any(turn["status"].startswith("INCOMPLETE") and
               turn["id"] not in pending_by_id for turn in self.turns):
            raise ValueError("incomplete model turn has no terminal pending record")
        if expected_direction != self.direction_counts or \
                expected_function != self.function_counts:
            raise ValueError("development role history and role count disagree")
        if any(value > self.budget.direction_turns_per_scope
               for value in expected_direction.values()):
            raise ValueError("development Direction role cap exceeded")
        for scope_id, counts in expected_function.items():
            sp = sum(counts.get(role, 0) for role in SP_ROLES)
            hp = sum(counts.get(role, 0) for role in HP_ROLES)
            if (self.budget.profile == PER_FUNCTION_V2_PROFILE and (
                    sp > self.budget.sp_per_function or
                    hp > self.budget.hp_per_function or
                    sp + hp > self.budget.combined_per_function or
                    counts.get("function_analysis", 0) >
                        self.budget.hp_analysis_per_function or
                    counts.get("assertion_generator", 0) >
                        self.budget.hp_assertion_per_function) or
                    self.function_states[scope_id] not in {
                        "SELECTED_NOT_STARTED", "SCAN_RECORDED",
                        "INCOMPLETE_BUDGET", "INCOMPLETE_INTERRUPTED",
                        "INCOMPLETE_PHYSICAL_STOP",
                        "INCOMPLETE_PRODUCT_RESPONSE"}):
                raise ValueError("development function role cap or state invalid")
            if (self.function_states[scope_id] == "INCOMPLETE_PHYSICAL_STOP" and
                    "physical-stop:" + scope_id not in pending_by_id):
                raise ValueError("physical stop has no terminal pending record")
        attempts_by_turn: dict[str, list[dict]] = {}
        previous_turn_number = 0
        for index, row in enumerate(self.attempts, 1):
            original = turn_by_id.get(row.get("turn_id"))
            if (row.get("physical") != index or row.get("status") not in
                    {"STARTED", "COMPLETED", "ERROR",
                     "INTERRUPTED_UNCERTAIN_REMOTE_STATE"} or
                    original is None or
                    row.get("request_hash") != original["hash"] or
                    row.get("role") != original["role"] or
                    row.get("scope_id") != original["scope_id"] or
                    type(row.get("retry")) is not bool or
                    row.get("retry") is True and (index == 1 or
                        self.attempts[index - 2]["turn_id"] != row["turn_id"] or
                        self.attempts[index - 2]["status"] != "ERROR" or
                        self.attempts[index - 2].get("retry_eligible") is not True)):
                raise ValueError("development physical attempt chain invalid")
            if row["status"] == "STARTED" and index != self.physical:
                raise ValueError("earlier physical attempt remains in flight")
            if row.get("retry_eligible") is True:
                if (row["status"] != "ERROR" or
                        row["retry"] is True or
                        row.get("accepted") is not True or
                        row.get("visible") is not False or
                        row.get("response_saved") is not False or
                        row.get("internal_retry") is not False or
                        "stream disconnected before completion" not in
                            str(row.get("error", "")) or
                        row["physical"] >= self.budget.physical_max):
                    raise ValueError("development retry eligibility record invalid")
            turn_number = int(row["turn_id"][1:])
            rows = attempts_by_turn.setdefault(row["turn_id"], [])
            if (turn_number < previous_turn_number or
                    (not rows and row["retry"]) or
                    (rows and (not row["retry"] or len(rows) != 1))):
                raise ValueError("development retry sequence invalid")
            rows.append(row)
            previous_turn_number = turn_number
        for turn in self.turns:
            rows = attempts_by_turn.get(turn["id"], [])
            if (turn["status"] == "COMPLETED" and
                    (not rows or rows[-1]["status"] != "COMPLETED") or
                    turn["status"].startswith("INCOMPLETE") and
                    rows and rows[-1]["status"] == "COMPLETED"):
                raise ValueError("development turn completion disagrees with attempts")
            if (turn["status"].startswith("INCOMPLETE") and
                    turn["scope_id"] in self.function_states and
                    self.function_states[turn["scope_id"]] == "SCAN_RECORDED"):
                raise ValueError("incomplete function cannot claim scan recorded")
        if self.active_turn is not None:
            turn = self.active_turn
            matching = [row for row in self.attempts if
                        row["turn_id"] == turn.get("id")]
            if (turn.get("id") != f"L{self.logical:06d}" or
                    turn.get("role") not in FUNCTION_ROLES | {DIRECTION_ROLE} or
                    (turn.get("scope_id") not in self.direction_counts if
                     turn.get("role") == DIRECTION_ROLE else
                     turn.get("scope_id") not in self.function_counts) or
                    not _SHA.fullmatch(str(turn.get("hash", ""))) or
                    type(turn.get("attempts")) is not int or
                    turn["attempts"] != len(matching) or len(matching) > 2 or
                    any(row["request_hash"] != turn["hash"] or
                        row["role"] != turn["role"] or
                        row["scope_id"] != turn["scope_id"] for row in matching) or
                    matching and matching[-1] != self.attempts[-1] or
                    matching and matching[-1]["status"] == "COMPLETED"):
                raise ValueError("development active turn disagrees with physical attempts")
        if self.active_turn is None and any(row["status"] == "STARTED"
                                             for row in self.attempts):
            raise ValueError("in-flight attempt without active turn")

    def checkpoint(self) -> None:
        if self.tainted:
            raise RuntimeError("development audit checkpoint is tainted")
        try:
            self._validate()
        except BaseException:
            self.tainted = True
            raise
        path = self.checkpoint_path
        try:
            _reject_linked_checkpoint_path(path)
        except ValueError:
            self.tainted = True
            raise
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_name(path.name + "." + uuid4().hex + ".tmp")
        data = {"kind": _CHECKPOINT_KINDS[self.budget.profile],
                "budget": self.budget.checkpoint_budget(),
                "started_at": self.started_at, "logical": self.logical,
                "physical": self.physical, "retries": self.retries,
                "direction_scopes": self.direction_scopes,
                "direction_counts": self.direction_counts,
                "selected_functions": self.selected_functions,
                "function_counts": self.function_counts,
                "function_states": self.function_states,
                "no_opportunity": self.no_opportunity,
                "pending_work": self.pending_work, "turns": self.turns,
                "attempts": self.attempts,
                "active_turn": self.active_turn}
        encoded = (json.dumps(data, sort_keys=True, indent=2) + "\n").encode("utf-8")
        try:
            with _checkpoint_lock(path):
                _reject_linked_checkpoint_path(path)
                if path.exists():
                    file_info = path.stat()
                    if (not stat.S_ISREG(file_info.st_mode) or
                            stat.S_IMODE(file_info.st_mode) != 0o600 or
                            file_info.st_nlink != 1):
                        raise ValueError("development checkpoint file is linked or unsafe")
                current = (hashlib.sha256(path.read_bytes()).hexdigest()
                           if path.exists() else None)
                if current != getattr(self, "_checkpoint_sha256", None):
                    raise ValueError("development checkpoint bytes changed by another owner")
                fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                             os.O_NOFOLLOW, 0o600)
                with os.fdopen(fd, "wb") as stream:
                    stream.write(encoded)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(temporary, path)
                parent_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.fsync(parent_fd)
                finally:
                    os.close(parent_fd)
                # Dynamic attribute deliberately excluded from asdict(ledger),
                # which is compared against the durable JSON by product Scan.
                self._checkpoint_sha256 = hashlib.sha256(encoded).hexdigest()
        except BaseException:
            self.tainted = True
            temporary.unlink(missing_ok=True)
            raise

    @classmethod
    def restore(cls, checkpoint_path: Path,
                budget: DevelopmentBudget) -> "DevelopmentRequestLedger":
        _reject_linked_checkpoint_path(checkpoint_path)
        if (not checkpoint_path.is_file() or
                stat.S_IMODE(checkpoint_path.stat().st_mode) != 0o600 or
                checkpoint_path.stat().st_nlink != 1):
            raise ValueError("development checkpoint unavailable or linked")
        with _checkpoint_lock(checkpoint_path):
            if checkpoint_path.stat().st_nlink != 1:
                raise ValueError("development checkpoint hardlink rejected")
            checkpoint_bytes = checkpoint_path.read_bytes()
        data = json.loads(checkpoint_bytes.decode("utf-8"))
        if (data.pop("kind", None) != _CHECKPOINT_KINDS[budget.profile] or
                data.pop("budget", None) != budget.checkpoint_budget()):
            raise ValueError("development checkpoint contract changed")
        ledger = cls(budget=budget, checkpoint_path=checkpoint_path, **data)
        ledger._checkpoint_sha256 = hashlib.sha256(checkpoint_bytes).hexdigest()
        # Older checkpoints mislabeled an interrupted turn as ordinary budget
        # pending. Derive the terminal state from immutable turn/attempt history
        # before validation, then persist the normalized record on restore.
        legacy_normalized = False
        historic_turns = {turn.get("id"): turn for turn in ledger.turns
                          if type(turn) is dict}
        for row in ledger.pending_work:
            if type(row) is not dict or row.get("state") != "PENDING_BUDGET":
                continue
            historic = historic_turns.get(row.get("id"))
            if historic is not None and str(historic.get("status", "")).startswith("INCOMPLETE"):
                row["state"] = ("INCOMPLETE_UNCERTAIN_REMOTE_STATE" if
                                any(attempt.get("turn_id") == historic["id"]
                                    for attempt in ledger.attempts) else
                                "INCOMPLETE_PRE_SEND_MODEL_TURN")
                legacy_normalized = True
        ledger._validate()
        if ledger.active_turn is not None:
            turn = ledger.active_turn
            if ledger.attempts and ledger.attempts[-1]["turn_id"] == turn["id"] and \
                    ledger.attempts[-1]["status"] == "STARTED":
                ledger.attempts[-1]["status"] = "INTERRUPTED_UNCERTAIN_REMOTE_STATE"
            if turn["scope_id"] in ledger.function_states:
                ledger.function_states[turn["scope_id"]] = "INCOMPLETE_INTERRUPTED"
            ledger.turns[-1]["status"] = "INCOMPLETE_INTERRUPTED"
            ledger.active_turn = None
            ledger._record_interrupted_turn(turn,
                                            "INCONCLUSIVE_INTERRUPTED_MODEL_TURN")
            ledger.checkpoint()
        elif legacy_normalized:
            ledger.checkpoint()
        return ledger

    def register_direction(self, scope_id: str) -> None:
        self._reject_new_work_after_terminal_turn()
        self.wall()
        if (self.active_turn or not scope_id or scope_id in self.direction_counts or
                scope_id in self.function_counts):
            raise ValueError("direction scope not eligible")
        self.direction_scopes.append(scope_id)
        self.direction_counts[scope_id] = 0
        self.checkpoint()

    def select_function(self, function_id: str) -> bool:
        self._reject_new_work_after_terminal_turn()
        self.wall()
        if (self.active_turn or not function_id or function_id in self.function_counts or
                function_id in self.direction_counts or
                function_id in self.no_opportunity):
            raise ValueError("function selection not eligible")
        if (self.budget.physical_max - self.physical <
                self.budget.initial_starts_required or
                self.budget.logical_max - self.logical <
                self.budget.initial_starts_required):
            self.no_opportunity[function_id] = "NO_OPPORTUNITY_BUDGET"
            self.checkpoint()
            return False
        self.selected_functions.append(function_id)
        self.function_counts[function_id] = {}
        self.function_states[function_id] = "SELECTED_NOT_STARTED"
        self.checkpoint()
        return True

    def mark_no_opportunity(self, function_id: str, reason: str) -> None:
        if (not function_id or function_id in self.function_counts or
                function_id in self.no_opportunity):
            raise ValueError("no-opportunity identity not eligible")
        self.no_opportunity[function_id] = reason
        self.checkpoint()

    def mark_selected_physical_stop(self, scope_id: str, reason: str) -> None:
        """Persist a STOP after selection but before evaluator Scan settlement.

        Earlier turns may have completed; this method starts no model turn.
        The selected job remains incomplete, and the terminal pending receipt
        forbids all later model or job starts.
        """
        if (self.tainted or self.active_turn is not None or
                scope_id not in self.function_states or
                self.function_states[scope_id] != "SELECTED_NOT_STARTED" or
                reason not in PHYSICAL_STOP_REASONS or
                any(row["id"] == "physical-stop:" + scope_id
                    for row in self.pending_work)):
            raise ValueError("selected physical stop not eligible")
        self.function_states[scope_id] = "INCOMPLETE_PHYSICAL_STOP"
        self.pending_work.append({"id": "physical-stop:" + scope_id,
                                  "scope_id": scope_id, "work_kind": "SCAN",
                                  "state": "INCOMPLETE_PHYSICAL_STOP",
                                  "reason": reason})
        self.checkpoint()

    def mark_pending(self, item_id: str, scope_id: str, work_kind: str,
                     reason: str, *, save: bool = True) -> None:
        if (not item_id or work_kind not in WORK_KINDS or
                _TURN_ID.fullmatch(item_id) or
                scope_id not in self.direction_counts and
                scope_id not in self.function_counts or
                any(turn["id"] == item_id for turn in self.turns) or
                any(row["id"] == item_id for row in self.pending_work)):
            raise ValueError("pending work identity not eligible")
        self.pending_work.append({"id": item_id, "scope_id": scope_id,
                                  "work_kind": work_kind,
                                  "state": "PENDING_BUDGET", "reason": reason})
        if save:
            self.checkpoint()

    def _record_interrupted_turn(self, turn: dict, reason: str) -> None:
        if any(row["id"] == turn["id"] for row in self.pending_work):
            raise ValueError("interrupted turn is already recorded")
        state = ("INCOMPLETE_PRODUCT_RESPONSE" if
                 self.turns[-1]["status"] == "INCOMPLETE_PRODUCT_RESPONSE" else
                 "INCOMPLETE_UNCERTAIN_REMOTE_STATE" if turn["attempts"] else
                 "INCOMPLETE_PRE_SEND_MODEL_TURN")
        self.pending_work.append({"id": turn["id"], "scope_id": turn["scope_id"],
                                  "work_kind": ("DIRECTION" if turn["role"] ==
                                                DIRECTION_ROLE else "SCAN"),
                                  "state": state, "reason": reason})

    def _reject_new_work_after_terminal_turn(self) -> None:
        # There is no audited continuation/claim contract for interrupted
        # model work. A changed request hash or another scope is not a safe
        # substitute for settling a possibly live physical request. A STOP
        # between completed jobs has no selected scope for a pending turn;
        # its durable no-opportunity reason is terminal for this ledger too.
        if (any(row["state"] in TERMINAL_PENDING_STATES for row in self.pending_work) or
                NO_OPPORTUNITY_PHYSICAL_STOP in self.no_opportunity.values()):
            raise ValueError("development terminal model turn prevents new work")

    def begin_turn(self, scope_id: str, role: str, request_hash: str) -> str:
        self._reject_new_work_after_terminal_turn()
        if any(row["id"] == f"L{self.logical + 1:06d}"
               for row in self.pending_work):
            raise ValueError("next model turn identity collides with pending work")
        if (self.tainted or self.active_turn or
                not isinstance(request_hash, str) or not _SHA.fullmatch(request_hash)):
            raise ValueError("development model turn not eligible")
        if role == DIRECTION_ROLE:
            if (scope_id not in self.direction_counts or
                    self.direction_counts[scope_id] >=
                        self.budget.direction_turns_per_scope):
                raise ValueError("unregistered or exhausted Direction scope")
        elif role in FUNCTION_ROLES:
            if scope_id not in self.function_counts:
                raise ValueError("unselected function scope")
            counts = self.function_counts[scope_id]
            sp = sum(counts.get(item, 0) for item in SP_ROLES)
            hp = sum(counts.get(item, 0) for item in HP_ROLES)
            if (self.budget.profile == PER_FUNCTION_V2_PROFILE and (
                    sp + hp >= self.budget.combined_per_function or
                    role in SP_ROLES and sp >= self.budget.sp_per_function or
                    role in HP_ROLES and hp >= self.budget.hp_per_function or
                    role == "function_analysis" and
                        counts.get(role, 0) >= self.budget.hp_analysis_per_function or
                    role == "assertion_generator" and
                        counts.get(role, 0) >= self.budget.hp_assertion_per_function)):
                raise ValueError("function role limit reached")
        else:
            raise ValueError("unregistered model role")
        self.wall()
        if (self.physical >= self.budget.physical_max or
                self.logical >= self.budget.logical_max):
            raise DevelopmentBudgetExhausted("development model turn not eligible")
        if role == DIRECTION_ROLE:
            self.direction_counts[scope_id] += 1
        else:
            counts[role] = counts.get(role, 0) + 1
        self.logical += 1
        turn_id = f"L{self.logical:06d}"
        self.active_turn = {"id": turn_id, "scope_id": scope_id,
                            "role": role, "hash": request_hash,
                            "attempts": 0}
        self.turns.append({"id": turn_id, "scope_id": scope_id,
                           "role": role, "hash": request_hash,
                           "status": "ACTIVE"})
        self.checkpoint()
        return turn_id

    def start_attempt(self, request_hash: str, *, retry: bool = False) -> int:
        """Durably debit the physical start; caller may send only after return."""
        self.wall()
        turn = self.active_turn
        if self.tainted or turn is None:
            raise ValueError("physical start rejected")
        if self.physical >= self.budget.physical_max:
            raise DevelopmentBudgetExhausted("physical start rejected")
        if turn["hash"] != request_hash:
            raise ValueError("retry request content changed")
        if retry:
            previous = self.attempts[-1] if self.attempts else None
            if (turn["attempts"] != 1 or previous is None or
                    previous["turn_id"] != turn["id"] or
                    previous.get("retry_eligible") is not True or
                    self.retries >= self.budget.retries_max):
                raise ValueError("retry rejected")
            self.retries += 1
        elif turn["attempts"]:
            raise ValueError("second physical start requires retry")
        self.physical += 1
        turn["attempts"] += 1
        self.attempts.append({"turn_id": turn["id"], "physical": self.physical,
                              "scope_id": turn["scope_id"], "role": turn["role"],
                              "request_hash": request_hash, "retry": retry,
                              "status": "STARTED"})
        self.checkpoint()
        return self.physical

    def finish_attempt(self, *, completed: bool, error: str = "",
                       accepted: bool = False, visible: bool = False,
                       response_saved: bool = False,
                       internal_retry: bool = False) -> bool:
        turn = self.active_turn
        row = self.attempts[-1] if self.attempts else None
        if (turn is None or row is None or row["turn_id"] != turn["id"] or
                row["status"] != "STARTED"):
            raise ValueError("no active physical attempt")
        eligible = (not completed and accepted and not visible and
                    not response_saved and not internal_retry and
                    "stream disconnected before completion" in error and
                    turn["attempts"] == 1 and
                    self.retries < self.budget.retries_max and
                    self.physical < self.budget.physical_max)
        row.update(status="COMPLETED" if completed else "ERROR",
                   error=error, accepted=accepted, visible=visible,
                   response_saved=response_saved,
                   internal_retry=internal_retry,
                   retry_eligible=eligible)
        if completed:
            self.turns[-1]["status"] = "COMPLETED"
            self.active_turn = None
        self.checkpoint()
        return eligible

    def abandon_turn(self, reason: str, *, budget_exhausted: bool = False,
                     completed_server_product_error: bool = False) -> None:
        turn = self.active_turn
        if turn is None:
            raise ValueError("no active turn to abandon")
        if completed_server_product_error:
            row = self.attempts[-1] if self.attempts else None
            if (budget_exhausted or turn["role"] == DIRECTION_ROLE or
                    row is None or row["turn_id"] != turn["id"] or
                    row["status"] != "ERROR" or
                    row.get("server_terminal_status") != "completed" or
                    not isinstance(row.get("app_server_turn_id"), str) or
                    not row["app_server_turn_id"] or
                    not isinstance(row.get("product_response_error_type"), str) or
                    not _SHA.fullmatch(str(row.get(
                        "product_response_error_sha256", ""))) or
                    row["request_hash"] != turn["hash"]):
                raise ValueError("completed-server product error not proven")
        if self.attempts and self.attempts[-1]["turn_id"] == turn["id"] and \
                self.attempts[-1]["status"] == "STARTED":
            self.attempts[-1]["status"] = "INTERRUPTED_UNCERTAIN_REMOTE_STATE"
        if turn["scope_id"] in self.function_states:
            self.function_states[turn["scope_id"]] = (
                "INCOMPLETE_PRODUCT_RESPONSE" if completed_server_product_error
                else "INCOMPLETE_BUDGET" if budget_exhausted
                else "INCOMPLETE_INTERRUPTED")
        self.turns[-1]["status"] = (
            "INCOMPLETE_PRODUCT_RESPONSE" if completed_server_product_error
            else "INCOMPLETE_BUDGET" if budget_exhausted
            else "INCOMPLETE_INTERRUPTED")
        self.active_turn = None
        self._record_interrupted_turn(turn, reason)
        self.checkpoint()

    def mark_scan_recorded(self, function_id: str) -> None:
        if (function_id not in self.function_states or self.active_turn or
                self.function_states[function_id].startswith("INCOMPLETE")):
            raise ValueError("scan completion not eligible")
        self.function_states[function_id] = "SCAN_RECORDED"
        self.checkpoint()

    def summary(self, pool_ids: list[str]) -> dict:
        if len(pool_ids) != len(set(pool_ids)) or not set(
                self.selected_functions + list(self.no_opportunity)).issubset(pool_ids):
            raise ValueError("development pool identity changed")
        unstarted = [item for item in pool_ids if item not in
                     self.function_counts and item not in self.no_opportunity]
        pending = bool(self.pending_work)
        if not pool_ids:
            status = "POOL_EMPTY"
        elif (self.active_turn or any(state.startswith("INCOMPLETE")
                                     for state in self.function_states.values()) or
              any(row["state"] in TERMINAL_PENDING_STATES
                  for row in self.pending_work)):
            status = "INCOMPLETE"
        elif self.no_opportunity:
            status = ("BUDGET_EXHAUSTED" if all(
                reason == "NO_OPPORTUNITY_BUDGET"
                for reason in self.no_opportunity.values()) else "INCOMPLETE")
        elif self.physical >= self.budget.physical_max and (unstarted or pending):
            status = "BUDGET_EXHAUSTED"
        elif unstarted:
            status = "IN_PROGRESS"
        elif pending:
            status = "POOL_SELECTION_EXHAUSTED_PENDING_WORK"
        elif not self.direction_scopes or any(
                self.direction_counts[scope] == 0 for scope in self.direction_scopes):
            status = "DIRECTION_NOT_ACCOUNTED"
        elif all(state == "SCAN_RECORDED" for state in self.function_states.values()):
            # This ledger does not inspect the actual Direction/Scan evidence.
            status = "ACCOUNTING_COMPLETE_AWAITING_EVIDENCE"
        else:
            status = "IN_PROGRESS"
        return {"status": status, "K_observed": len(self.selected_functions),
                "physical": self.physical, "logical": self.logical,
                "retries": self.retries,
                "selected_functions": list(self.selected_functions),
                "no_opportunity": dict(self.no_opportunity),
                "unstarted": unstarted,
                "pending_work": list(self.pending_work),
                "function_states": dict(self.function_states)}
