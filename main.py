import angr
import sys

def main(argv):
    binary_path = argv[1]
    project = angr.Project(binary_path, auto_load_libs=False)
    initial_state = project.factory.entry_state()
    simulation = project.factory.simgr(initial_state)

    success_condition = input("Enter the success string condition: ").encode()
    fail_condition = input("Enter the failure string condition: ").encode()

    def is_successful(state):
        stdout_output = state.posix.dumps(sys.stdout.fileno())
        return success_condition in stdout_output

    def should_abort(state):
        stdout_output = state.posix.dumps(sys.stdout.fileno())
        return fail_condition in stdout_output

    simulation.explore(find=is_successful, avoid=should_abort)

    if simulation.found:
        solution_state = simulation.found[0]
        print(f"Solution found with input: {solution_state.posix.dumps(sys.stdin.fileno())}")
    else:
        print("No solution found.")

if __name__ == "__main__":
    main(sys.argv)
