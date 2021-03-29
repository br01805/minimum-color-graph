class Backtracking:

    def __init__(self, vertices):
        self.V = vertices
        self.graph = [[0 for column in range(vertices)] \
                      for row in range(vertices)]

    # Checks if color assignment is safe
    def safe(self, v, colour, c):
        for i in range(self.V):
            if self.graph[v][i] == 1 and colour[i] == c:
                return False
        return True

    # recursive utility for solving backtracking
    def graph_solve_color(self, m, color, v):
        if v == self.V:
            return True

        for c in range(1, m + 1):
            if self.safe(v, color, c) == True:
                color[v] = c
                if self.graph_solve_color(m, color, v + 1) == True:
                    return True
                color[v] = 0

    def graph_backtrack(self, m):
        color = [0] * self.V
        if self.graph_solve_color(m, color, 0) == None:
            return False

        # Print the solution
        for u in range(self.V):
            print("Vertex", u, " --->  Color", color[u])
        return color