from typing import Dict, List, Tuple


class Solutions:
    def __init__(self):
        self.solutions: Dict[str, Dict[str,List[str| Tuple[float, str]]]] = dict()

    def write(self, exercise_id:str, solution_line:str):
        self.solutions.setdefault(exercise_id, {"header":[], 'events':[]})['header'].append(solution_line)

    def write_event(self, exercise_id:str, time:float, solution_line:str):
        self.solutions.setdefault(exercise_id, {"header":[], 'events':[]})['events'].append((time, solution_line))

    def save_on_file(self, filename):
        with open(filename, "w") as f:
            for exercise_id, lines in self.solutions.items():
                f.write(f"# Exercise ID: {exercise_id}\n")
                for line in lines['header']:
                    f.write(f'{line}\n')

                if len(lines['events'])>0:
                    f.write("Events:\n")
                    for time, line in sorted(lines['events']):
                        f.write(f"\tTime {time:.3f}: {line}\n")
                #f.writelines(lines)
                f.write(f"\n{'#'*33} END EXERCISE {'#'*33}\n")
                f.write(f"{'#'*80}\n\n")



solutions = Solutions()