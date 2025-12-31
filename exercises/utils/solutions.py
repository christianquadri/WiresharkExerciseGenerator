from typing import Dict, List


class Solutions:
    def __init__(self):
        self.solutions: Dict[str, List[str]] = {}

    def write(self, exercise_id:str, solution_line:str):
        self.solutions.setdefault(exercise_id, []).append(f'{solution_line}\n')

    def save_on_file(self, filename):
        with open(filename, "w") as f:
            for exercise_id, lines in self.solutions.items():
                f.write(f"# Exercise ID: {exercise_id}\n")
                f.writelines(lines)
                f.write(f"\n{'#'*33} END EXERCISE {'#'*33}\n")
                f.write(f"{'#'*80}\n\n")



solutions = Solutions()