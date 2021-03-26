class Greedy:
    def __init__(self, logger):
        self.logger = logger

    def addEdge(self, adj, v, w):

        adj[v].append(w)

        # Note: the graph is undirected
        adj[w].append(v)
        return adj

    # Assigns colors (starting from 0) to all
    # vertices and prints the assignment of colors
    def greedyColoring(self, adj, V):

        result = [-1] * V

        # Assign the first color to first vertex
        result[0] = 0;


        # A temporary array to store the available colors.
        # True value of available[cr] would mean that the
        # color cr is assigned to one of its adjacent vertices
        available = [False] * V

        # Assign colors to remaining V-1 vertices
        for u in range(1, V):

            # Process all adjacent vertices and
            # flag their colors as unavailable
            for i in adj[u]:
                if (result[i] != -1):
                    available[result[i]] = True

            # Find the first available color
            cr = 0
            while cr < V:
                if (available[cr] == False):
                    break

                cr += 1

            # Assign the found color
            result[u] = cr

            # Reset the values back to false
            # for the next iteration
            for i in adj[u]:
                if (result[i] != -1):
                    available[result[i]] = False

        # Pint the result
        for u in range(V):
            print("Vertex", u, " --->  Color", result[u])