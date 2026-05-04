"""Basic usage for Agent Blackbox."""

from agent_blackbox import AgentBlackbox

blackbox = AgentBlackbox(storage="./examples_logs")


@blackbox.trace(agent_name="PlannerAgent")
def plan_task(requirement: str) -> str:
    return f"Plan for: {requirement}"


plan = plan_task("build a demo")
planner_hash = list(blackbox.events.keys())[-1]


@blackbox.trace(agent_name="CoderAgent", parent_event_hash=planner_hash)
def write_code(plan: str) -> str:
    return "print('hello world')"


code = write_code(plan)
coder_hash = list(blackbox.events.keys())[-1]

report = blackbox.review_incident(coder_hash)

print("Event hash:", coder_hash)
print("Candidate failure node:", report["candidate_failure_node"])
print("Boundary:", report["boundary"])
print("Chain:", report["chain"])
