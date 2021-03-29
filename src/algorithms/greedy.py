class Greedy:
    def __init__(self, logger):
        self.logger = logger

    def add_edge(self, adj, v, w):

        adj[v].append(w)

        # Note: the graph is undirected
        adj[w].append(v)
        return adj

    #Assign colors to vertices
    def greedy_coloring(self, adj, V):

        res = [-1] * V

        res[0] = 0  # Assign the first color to first vertex


        # A temporary array to store the available colors.
        # True value of available[cr] would mean that the
        # color cr is assigned to one of its adjacent vertices
        available = [False] * V

        # Assign colors to remaining V-1 vertices
        for u in range(1, V):

            # Process all adjacent vertices and flag their colors as unavailable
            for i in adj[u]:
                if res[i] != -1:
                    available[res[i]] = True

            # Find the first available color
            cr = 0
            while cr < V:
                if (available[cr] == False):
                    break

                cr += 1
            res[u] = cr  # Assign the found color

            # Reset the values back to false for the next iteration
            for i in adj[u]:
                if (res[i] != -1):
                    available[res[i]] = False

        for u in range(V):
            print("Vertex", u, " --->  Color", res[u])

        return res