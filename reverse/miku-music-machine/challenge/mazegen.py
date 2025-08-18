from mazelib import Maze
from mazelib.generate.Prims import Prims
from mazelib.generate.Kruskal import Kruskal
from mazelib.solve.ShortestPaths import ShortestPaths
import random

SIZE = 21
NUM_WAYPOINTS = 5

seed = random.randint(0, 2**32 - 1)
Maze.set_seed(seed)

# step 1: generate a random maze
m = Maze()
m.generator = Kruskal(SIZE // 2, SIZE // 2)
m.solver = ShortestPaths()

# generate a maze that's solveable from start to end
while True:
    m.generate()
    m.start = (1, 1)
    m.end = (SIZE - 2, SIZE - 2)
    try:
        m.solve()
        break
    except:
        continue

random.seed(seed)

# step 2: add waypoints

# we work backwards here, picking a point that blocks the path from the current position to the target position
# then, we place a switch somewhere reachable from the current position that is not directly on the path and still
# reachable when the door is closed. We then adjust the target to be that switch instead.
switches = []
wall_positions = set()
switch_positions = set()

current_pos = m.start
target = m.end
for i in range(NUM_WAYPOINTS):
    # find shortest path from current position to end
    m.solver = ShortestPaths()
    m.start = current_pos
    m.end = target
    m.solve()

    # grab a random tile on the path that will block the path from start to end
    solution = m.solutions[0]
    wall_pos = None
    random.shuffle(solution)
    for candidate in solution:
        # find a random position on the path to block
        if candidate == current_pos or candidate == target or candidate in wall_positions or candidate in switch_positions:
            continue

        # block the position
        m.grid[candidate[0]][candidate[1]] = 1

        # check if the maze is now unsolvable
        try:
            m.solve()
            continue
        except:
            pass
        finally:
            m.grid[candidate[0]][candidate[1]] = 0 # unblock the position
        
        wall_pos = candidate
        break
    if wall_pos is None:
        raise Exception("Could not find a wall position")
    
    # let's put the wall there
    m.grid[wall_pos[0]][wall_pos[1]] = 1

    # now, grab a random position on the map that is reachable from the current position
    candidate_positions = [(x, y) for x in range(1, SIZE - 1) for y in range(1, SIZE - 1) if m.grid[x][y] == 0]
    random.shuffle(candidate_positions)
    switch_pos = None
    for candidate in candidate_positions:
        if candidate == current_pos \
            or candidate == target \
            or candidate in wall_positions \
            or candidate in switch_positions \
            or candidate in solution:
            continue

        # let's see if this is reachable from the current position
        m.start = current_pos
        m.end = candidate

        try:
            m.solve()
            switch_pos = candidate
            break # reachable
        except:
            continue # not reachable

    if switch_pos is None:
        raise Exception("Could not find a switch position")

    switches.append((switch_pos, wall_pos))
    switch_positions.add(switch_pos)
    wall_positions.add(wall_pos)

    target = switch_pos

m = m.tostring()
m = m.split('\n')
m = [list(row) for row in m]

m[1][1] = 'a'
m[SIZE - 2][SIZE - 2] = chr(ord('a') + NUM_WAYPOINTS + 1)

for i, (switch_pos, wall_pos) in enumerate(reversed(switches)):
    m[switch_pos[0]][switch_pos[1]] = chr(ord('b') + i)
    m[wall_pos[0]][wall_pos[1]] = chr(ord('B') + i)

m = '\n'.join([''.join(row) for row in m])
print(m)
# print(seed)