# brain/planner.py

def make_plan(user_input):
    # For now, just returns a dummy plan.
    # Later, connect it with memory or tools.
    if "remind" in user_input.lower():
        return "I'll remind you later!"
    elif "plan" in user_input.lower():
        return "Here's a plan outline."
    else:
        return "Thinking... let me analyze that."