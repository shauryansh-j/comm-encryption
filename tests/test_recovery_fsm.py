"""
Test Suite: Recovery Finite State Machine (FSM) Transitions and Lockdown Logic.
"""
from raspberry_pi.recovery_fsm import RecoveryFSM, FSMState


def test_fsm_normal_lifecycle():
    transitions = []

    def log_trans(old_s, new_s, r):
        transitions.append((old_s, new_s))

    fsm = RecoveryFSM(on_state_change=log_trans)
    assert fsm.current_state == FSMState.IDLE
    assert not fsm.is_forwarding_allowed

    # 1. Valid packet transitions IDLE -> RUN
    fsm.on_valid_packet()
    assert fsm.current_state == FSMState.RUN
    assert fsm.is_forwarding_allowed

    # 2. Transient fault transitions RUN -> SUSPECT
    fsm.on_fault_detected("Transient bad checksum")
    assert fsm.current_state == FSMState.SUSPECT
    assert not fsm.is_forwarding_allowed

    # 3. Subsequent valid packet recovers SUSPECT -> RUN
    fsm.on_valid_packet()
    assert fsm.current_state == FSMState.RUN
    assert fsm.is_forwarding_allowed


def test_fsm_persistent_faults_trigger_lockdown():
    fsm = RecoveryFSM(max_recovery_attempts=3)
    fsm.on_valid_packet()
    assert fsm.current_state == FSMState.RUN

    # Trigger faults until lockdown
    fsm.on_fault_detected("Fault 1")
    assert fsm.current_state == FSMState.SUSPECT

    fsm.on_fault_detected("Fault 2")
    assert fsm.current_state == FSMState.HALT

    fsm.on_fault_detected("Fault 3")
    assert fsm.current_state == FSMState.LOCK
    assert not fsm.is_forwarding_allowed

    # Additional valid packets are IGNORED in LOCK
    fsm.on_valid_packet()
    assert fsm.current_state == FSMState.LOCK

    # Operator reset restores IDLE
    res = fsm.operator_reset("SECURE_RESET")
    assert res is True
    assert fsm.current_state == FSMState.IDLE

